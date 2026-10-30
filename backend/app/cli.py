"""Admin CLI.

    python -m app.cli create-user --email you@example.com --role admin [--name "Your Name"] [--org SLUG]
    python -m app.cli platform-admin you@example.com        # make a user a platform owner (--revoke to undo)
    python -m app.cli org-list                              # organisations with usage counts
    python -m app.cli reset-password --email you@example.com
    python -m app.cli reset-mfa --email you@example.com   # lost authenticator (break-glass)
    python -m app.cli delete-user --email old@example.com [--yes]   # permanently delete a deactivated user
    python -m app.cli migrate        # apply schema migrations (Alembic on PostgreSQL)
    python -m app.cli rotate-notification-key   # after prepending a new NOTIFICATIONS_ENCRYPTION_KEY
    python -m app.cli agent-release-import BUNDLE.tar.gz   # or - for stdin (cnapp-ctl agent-release import)
    python -m app.cli agent-release-list
    python -m app.cli device-scripts-import BUNDLE.tar.gz  # or - (cnapp-ctl scripts import)
    python -m app.cli device-scripts-list
    python -m app.cli agent-release-check                  # GitHub Releases auto-import check now (cnapp-ctl agent-release check)
    python -m app.cli notify-server-update --status rolled_back --from-tag A --to-tag B  # (cnapp-ctl update)

Passwords are prompted for (never passed as arguments, so they stay out of shell
history). For automation, pipe the password with --password-stdin.
"""
from __future__ import annotations

import argparse
import getpass
import sys

from sqlalchemy import select

from . import auth, config, db, tenancy
from .models import ROLES, Organization, User, utcnow


def _read_password(from_stdin: bool) -> str:
    if from_stdin:
        pw = sys.stdin.readline().rstrip("\n")
    else:
        pw = getpass.getpass("Password: ")
        if getpass.getpass("Repeat password: ") != pw:
            raise SystemExit("error: passwords do not match")
    problem = auth.password_problem(pw)
    if problem:
        raise SystemExit(f"error: {problem}")
    return pw


def _org_by_slug(slug: str) -> Organization:
    with db.get_session(unscoped=True) as s:
        org = s.scalar(select(Organization).where(Organization.slug == slug.strip().lower()))
        if org is None:
            raise SystemExit(f"error: no organisation with slug {slug!r} (python -m app.cli org-list)")
        return org


def _user_session(email: str):
    """(session scoped to the user's organisation, user) for user maintenance commands."""
    s = db.get_session(unscoped=True)
    user = s.scalar(select(User).where(User.email == email))
    if user is None:
        s.close()
        raise SystemExit(f"error: no user {email}")
    rows = auth.memberships(s, user.id)
    if rows:
        tenancy.set_org(s, rows[0][1].id)
        user = s.scalar(select(User).where(User.email == email))
    return s, user


def create_user(args: argparse.Namespace) -> int:
    email = auth.normalize_email(args.email)
    if "@" not in email:
        raise SystemExit("error: invalid email")
    org = _org_by_slug(args.org)
    with db.get_session(org.id) as s:
        if s.scalar(select(User).where(User.email == email)):
            raise SystemExit(f"error: user {email} already exists (use reset-password)")
        pw = _read_password(args.password_stdin)
        user = User(email=email, name=args.name or "", password_hash=auth.hash_password(pw),
                    password_changed_at=utcnow())
        s.add(user)
        s.flush()
        auth.set_membership(s, user, org.id, args.role)
        auth.audit(s, "user_created", actor_email="cli", target=email, role=args.role)
        s.commit()
    print(f"Created {args.role} user {email} in organisation {org.name} ({org.slug})")
    return 0


def platform_admin(args: argparse.Namespace) -> int:
    """Grant (or revoke) the platform-owner flag: manage organisations in the platform console."""
    email = auth.normalize_email(args.email)
    s, user = _user_session(email)
    with s:
        user.is_platform_admin = not args.revoke
        auth.audit(s, "platform_admin_revoked" if args.revoke else "platform_admin_granted", actor_email="cli",
                   target=email)
        s.commit()
    if args.revoke:
        print(f"{email} is no longer a platform administrator"
              + (" (still listed in PLATFORM_ADMIN_EMAILS)" if email in config.settings.platform_admin_emails else ""))
    else:
        print(f"{email} is now a platform administrator (Platform > Organisations in the console)")
    return 0


def org_list(args: argparse.Namespace) -> int:
    from .services import organizations

    with db.get_session(unscoped=True) as s:
        for org, usage in organizations.list_with_usage(s):
            print(f"{org.slug:24} {org.status:9} users={usage['users']:<4} devices={usage['devices']:<5} "
                  f"assets={usage['assets']:<6} {org.name}" + ("  [default]" if org.is_default else ""))
    return 0


def reset_password(args: argparse.Namespace) -> int:
    email = auth.normalize_email(args.email)
    s, user = _user_session(email)
    with s:
        pw = _read_password(args.password_stdin)
        user.password_hash = auth.hash_password(pw)
        user.password_changed_at = utcnow()
        user.failed_login_count, user.locked_until, user.is_active = 0, None, True
        auth.revoke_user_sessions(s, user.id)
        auth.audit(s, "password_reset", actor_email="cli", target=email)
        s.commit()
    print(f"Password reset for {email}; the account is unlocked and active")
    return 0


def reset_mfa(args: argparse.Namespace) -> int:
    """Remove a user's TOTP authenticator and recovery codes (break-glass, e.g. the
    last admin lost their phone); also unlocks the account."""
    from . import mfa

    email = auth.normalize_email(args.email)
    s, user = _user_session(email)
    with s:
        had = user.mfa_enabled
        mfa.disable(s, user)
        user.failed_login_count, user.locked_until = 0, None
        auth.revoke_user_sessions(s, user.id)
        auth.audit(s, "mfa_reset", actor_email="cli", target=email, had_mfa=had)
        s.commit()
    print(f"MFA reset for {email}; they sign in with their password (and enrol again if required)")
    return 0


def delete_user(args: argparse.Namespace) -> int:
    """Permanently delete a deactivated account (same rules as the console's Delete)."""
    from .services import user_deletion

    email = auth.normalize_email(args.email)
    s, user = _user_session(email)
    with s:
        org_id = tenancy.org_id(s)
        if org_id is None:
            raise SystemExit(f"error: {email} is not a member of any organisation")
        try:
            user_deletion.check(s, user, org_id)
        except user_deletion.UserDeleteError as e:
            raise SystemExit(f"error: {e.message}") from None
        if not args.yes:
            try:
                typed = input(f"Permanently delete {email}? This cannot be undone. Type the email to confirm: ")
            except EOFError:
                typed = ""
            if auth.normalize_email(typed) != email:
                raise SystemExit("error: confirmation did not match; nothing was deleted")
        role = auth.memberships(s, user.id)[0][0].role
        removed = user_deletion.delete_account(s, user, org_id)
        auth.audit(s, "user_deleted", actor_email="cli", target=email, role=role, removed=removed)
        s.commit()
    print(f"Deleted user {email} (audit history is kept)")
    return 0


def migrate(args: argparse.Namespace) -> int:
    # init_engine() (called by main with migrate=True) already applied them.
    url = db.engine.url.render_as_string(hide_password=True) if db.engine is not None else "?"
    print(f"Database schema is up to date ({url})")
    return 0


def rotate_notification_key(args: argparse.Namespace) -> int:
    from .connectors import org_config
    from .notifications import crypto, dispatcher

    with db.get_session(unscoped=True) as s:  # every organisation's channels and connector settings
        try:
            n = dispatcher.rotate_channel_secrets(s)
            c = org_config.rotate_secrets(s)
        except (crypto.DecryptionFailed, crypto.EncryptionUnavailable) as exc:
            raise SystemExit(f"error: {exc}") from None
        auth.audit(s, "notification_key_rotated", actor_email="cli", channels=n, connector_configs=c)
        s.commit()
    print(f"Re-encrypted the secrets of {n} notification channel(s) and {c} cloud connector setting(s) with the "
          "first NOTIFICATIONS_ENCRYPTION_KEY")
    return 0


def agent_release_import(args: argparse.Namespace) -> int:
    """Import a signed agent release bundle (verified against the trusted release keys)."""
    from .services import agent_updates

    data = sys.stdin.buffer.read() if args.bundle == "-" else open(args.bundle, "rb").read()  # noqa: SIM115
    with db.get_session(tenancy.DEFAULT_ORG_ID) as s:
        try:
            rel = agent_updates.import_bundle(s, data, args.actor)
        except agent_updates.ReleaseError as e:
            s.rollback()
            auth.audit(s, "agent_release_rejected", actor_email=args.actor, reason=str(e)[:500], size_bytes=len(data))
            s.commit()
            raise SystemExit(f"error: {e}") from None
        auth.audit(s, "agent_release_imported", actor_email=args.actor, target=f"agent-release:{rel.id}",
                   version=rel.version, key_id=rel.key_id, bundle_sha256=rel.bundle_sha256,
                   artifacts=[f"{a.os}/{a.arch} {a.sha256}" for a in rel.artifacts])
        s.commit()
        plats = ", ".join(f"{a.os}/{a.arch}" for a in rel.artifacts)
        print(f"Imported agent release {rel.version} (id {rel.id}), signed by {rel.key_id}, "
              f"expires {rel.expires_at:%Y-%m-%d}; platforms: {plats}")
        from .services import agent_update_auto

        if agent_update_auto.get_settings(s).mode == "automatic":
            print("Automatic update mode: it goes to the Pilot ring now and to all devices after the soak period "
                  "(Devices > Agent updates).")
        else:
            print("Manual update mode: assign it to a rollout ring in the console (Devices > Agent updates).")
        s.commit()
    return 0


def agent_release_list(args: argparse.Namespace) -> int:
    from .models import AgentRelease
    from .services import agent_updates

    with db.get_session(tenancy.DEFAULT_ORG_ID) as s:
        rels = sorted(s.scalars(select(AgentRelease)), key=lambda r: agent_updates.version_sort_key(r.version),
                      reverse=True)
        for r in rels:
            state = "withdrawn" if r.withdrawn_at else ("expired" if r.expires_at <= utcnow() else "active")
            print(f"{r.version:24} {r.id}  {state:9} key={r.key_id} expires={r.expires_at:%Y-%m-%d} "
                  f"platforms={','.join(f'{a.os}/{a.arch}' for a in r.artifacts)}")
        if not rels:
            print("No agent releases imported.")
    return 0


def device_scripts_import(args: argparse.Namespace) -> int:
    """Import a signed device-script bundle (verified against the script-signing keys)."""
    from .services import device_scripts

    data = sys.stdin.buffer.read() if args.bundle == "-" else open(args.bundle, "rb").read()  # noqa: SIM115
    with db.get_session(tenancy.DEFAULT_ORG_ID) as s:
        try:
            b = device_scripts.import_bundle(s, data, args.actor)
        except device_scripts.ScriptBundleError as e:
            s.rollback()
            auth.audit(s, "device_script_bundle_rejected", actor_email=args.actor, reason=str(e)[:500],
                       size_bytes=len(data))
            s.commit()
            raise SystemExit(f"error: {e}") from None
        auth.audit(s, "device_script_bundle_imported", actor_email=args.actor, target=f"script-bundle:{b.id}",
                   version=b.version, key_id=b.key_id, bundle_sha256=b.bundle_sha256,
                   scripts=[f"{x.name} {x.risk} {x.sha256}" for x in b.scripts])
        s.commit()
        print(f"Imported device scripts {b.version} (id {b.id}), signed by {b.key_id}, "
              f"expires {b.expires_at:%Y-%m-%d}: {', '.join(f'{x.name} ({x.risk})' for x in b.scripts)}")
    return 0


def device_scripts_list(args: argparse.Namespace) -> int:
    from .services import device_scripts

    with db.get_session(tenancy.DEFAULT_ORG_ID) as s:
        bundles = device_scripts.bundles(s)
        latest = device_scripts.latest_bundle(s)
        for b in bundles:
            state = "expired" if b.expires_at <= utcnow() else ("active" if latest and b.id == latest.id else "older")
            print(f"{b.version:16} {b.id}  {state:8} key={b.key_id} expires={b.expires_at:%Y-%m-%d} "
                  f"scripts={','.join(x.name for x in b.scripts)}")
        if not bundles:
            print("No device-script bundles imported.")
    return 0


def agent_release_check(args: argparse.Namespace) -> int:
    """Check GitHub Releases for a new signed agent release and import it (same checks as an upload)."""
    from .services import agent_update_auto

    with db.get_session(tenancy.DEFAULT_ORG_ID) as s:
        res = agent_update_auto.check_github(s, actor=args.actor)
        auth.audit(s, "agent_release_check_requested", actor_email=args.actor, status=res["status"],
                   message=res["message"][:500])
        s.commit()
    print(f"{res['status']}: {res['message']}")
    return 0 if res["status"] != "error" else 1


def notify_server_update(args: argparse.Namespace) -> int:
    """Raise a server-update notification (cnapp-ctl update: failure or automatic rollback)."""
    from .notifications import server_update_source

    with db.get_session(tenancy.DEFAULT_ORG_ID) as s:
        if not server_update_source.server_update_event(s, args.status, args.from_tag, args.to_tag,
                                                        args.detail, automatic=args.automatic):
            print("could not queue the notification", file=sys.stderr)
            return 1
        auth.audit(s, f"server_update_{args.status}", actor_email=args.actor, from_tag=args.from_tag[:64],
                   to_tag=args.to_tag[:64], automatic=args.automatic)
        s.commit()
    print(f"queued server update notification: {args.status} {args.from_tag[:12]} -> {args.to_tag[:12]}")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python -m app.cli", description="CloudSecurity CNAPP admin CLI")
    sub = p.add_subparsers(dest="command", required=True)
    c = sub.add_parser("create-user", help="create a user (prompts for the password)")
    c.add_argument("--email", required=True)
    c.add_argument("--name", default="")
    c.add_argument("--role", choices=ROLES, default="viewer")
    c.add_argument("--org", default=tenancy.DEFAULT_ORG_SLUG, help="organisation slug (default: the default one)")
    c.add_argument("--password-stdin", action="store_true", help="read the password from stdin")
    c.set_defaults(func=create_user)
    pa = sub.add_parser("platform-admin", help="make a user a platform administrator (manages organisations)")
    pa.add_argument("email")
    pa.add_argument("--revoke", action="store_true", help="remove the flag instead")
    pa.set_defaults(func=platform_admin)
    ol = sub.add_parser("org-list", help="list organisations with usage counts")
    ol.set_defaults(func=org_list)
    r = sub.add_parser("reset-password", help="set a new password, unlock and reactivate a user")
    r.add_argument("--email", required=True)
    r.add_argument("--password-stdin", action="store_true", help="read the password from stdin")
    r.set_defaults(func=reset_password)
    f = sub.add_parser("reset-mfa", help="remove a user's authenticator app and recovery codes, unlock them")
    f.add_argument("--email", required=True)
    f.set_defaults(func=reset_mfa)
    du = sub.add_parser("delete-user", help="permanently delete a deactivated user (membership, sessions, MFA, SSO)")
    du.add_argument("--email", required=True)
    du.add_argument("--yes", action="store_true", help="do not ask to type the email to confirm")
    du.set_defaults(func=delete_user)
    m = sub.add_parser("migrate", help="apply database schema migrations (also done on startup by default)")
    m.set_defaults(func=migrate)
    k = sub.add_parser("rotate-notification-key",
                       help="re-encrypt notification channel secrets with the first NOTIFICATIONS_ENCRYPTION_KEY")
    k.set_defaults(func=rotate_notification_key)
    ai = sub.add_parser("agent-release-import", help="import a signed agent release bundle (.tar.gz, or - for stdin)")
    ai.add_argument("bundle")
    ai.add_argument("--actor", default="cli", help="name recorded in the audit log")
    ai.set_defaults(func=agent_release_import)
    al = sub.add_parser("agent-release-list", help="list imported agent releases")
    al.set_defaults(func=agent_release_list)
    di = sub.add_parser("device-scripts-import", help="import a signed device-script bundle (.tar.gz, or - for stdin)")
    di.add_argument("bundle")
    di.add_argument("--actor", default="cli", help="name recorded in the audit log")
    di.set_defaults(func=device_scripts_import)
    dl = sub.add_parser("device-scripts-list", help="list imported device-script bundles")
    dl.set_defaults(func=device_scripts_list)
    ac = sub.add_parser("agent-release-check",
                        help="check GitHub Releases for a new signed agent release and import it")
    ac.add_argument("--actor", default="cli", help="name recorded in the audit log")
    ac.set_defaults(func=agent_release_check)
    nu = sub.add_parser("notify-server-update",
                        help="raise a server-update notification (used by cnapp-ctl update on failure/rollback)")
    nu.add_argument("--status", required=True, choices=("rolled_back", "failed", "updated"))
    nu.add_argument("--from-tag", default="")
    nu.add_argument("--to-tag", default="")
    nu.add_argument("--detail", default="")
    nu.add_argument("--automatic", action="store_true", help="the update was started by the auto-update timer")
    nu.add_argument("--actor", default="cnapp-ctl", help="name recorded in the audit log")
    nu.set_defaults(func=notify_server_update)
    args = p.parse_args(argv)
    if args.func is migrate:
        db.init_engine(config.settings.database_url, migrate=True)
    else:
        db.init_engine(config.settings.database_url)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
