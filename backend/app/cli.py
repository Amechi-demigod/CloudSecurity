"""Admin CLI.

    python -m app.cli create-user --email you@example.com --role admin [--name "Your Name"]
    python -m app.cli reset-password --email you@example.com
    python -m app.cli reset-mfa --email you@example.com   # lost authenticator (break-glass)
    python -m app.cli migrate        # apply schema migrations (Alembic on PostgreSQL)
    python -m app.cli rotate-notification-key   # after prepending a new NOTIFICATIONS_ENCRYPTION_KEY
    python -m app.cli agent-release-import BUNDLE.tar.gz   # or - for stdin (cnapp-ctl agent-release import)
    python -m app.cli agent-release-list
    python -m app.cli agent-release-check                  # GitHub Releases auto-import check now (cnapp-ctl agent-release check)

Passwords are prompted for (never passed as arguments, so they stay out of shell
history). For automation, pipe the password with --password-stdin.
"""
from __future__ import annotations

import argparse
import getpass
import sys

from sqlalchemy import select

from . import auth, config, db
from .models import ROLES, User, utcnow


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


def create_user(args: argparse.Namespace) -> int:
    email = auth.normalize_email(args.email)
    if "@" not in email:
        raise SystemExit("error: invalid email")
    with db.get_session() as s:
        if s.scalar(select(User).where(User.email == email)):
            raise SystemExit(f"error: user {email} already exists (use reset-password)")
        pw = _read_password(args.password_stdin)
        s.add(User(email=email, name=args.name or "", role=args.role, password_hash=auth.hash_password(pw),
                   password_changed_at=utcnow()))
        auth.audit(s, "user_created", actor_email="cli", target=email, role=args.role)
        s.commit()
    print(f"Created {args.role} user {email}")
    return 0


def reset_password(args: argparse.Namespace) -> int:
    email = auth.normalize_email(args.email)
    with db.get_session() as s:
        user = s.scalar(select(User).where(User.email == email))
        if user is None:
            raise SystemExit(f"error: no user {email}")
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
    with db.get_session() as s:
        user = s.scalar(select(User).where(User.email == email))
        if user is None:
            raise SystemExit(f"error: no user {email}")
        had = user.mfa_enabled
        mfa.disable(s, user)
        user.failed_login_count, user.locked_until = 0, None
        auth.revoke_user_sessions(s, user.id)
        auth.audit(s, "mfa_reset", actor_email="cli", target=email, had_mfa=had)
        s.commit()
    print(f"MFA reset for {email}; they sign in with their password (and enrol again if required)")
    return 0


def migrate(args: argparse.Namespace) -> int:
    # init_engine() (called by main with migrate=True) already applied them.
    url = db.engine.url.render_as_string(hide_password=True) if db.engine is not None else "?"
    print(f"Database schema is up to date ({url})")
    return 0


def rotate_notification_key(args: argparse.Namespace) -> int:
    from .notifications import crypto, dispatcher

    with db.get_session() as s:
        try:
            n = dispatcher.rotate_channel_secrets(s)
        except (crypto.DecryptionFailed, crypto.EncryptionUnavailable) as exc:
            raise SystemExit(f"error: {exc}") from None
        auth.audit(s, "notification_key_rotated", actor_email="cli", channels=n)
        s.commit()
    print(f"Re-encrypted the secrets of {n} notification channel(s) with the first NOTIFICATIONS_ENCRYPTION_KEY")
    return 0


def agent_release_import(args: argparse.Namespace) -> int:
    """Import a signed agent release bundle (verified against the trusted release keys)."""
    from .services import agent_updates

    data = sys.stdin.buffer.read() if args.bundle == "-" else open(args.bundle, "rb").read()  # noqa: SIM115
    with db.get_session() as s:
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

    with db.get_session() as s:
        rels = sorted(s.scalars(select(AgentRelease)), key=lambda r: agent_updates.version_sort_key(r.version),
                      reverse=True)
        for r in rels:
            state = "withdrawn" if r.withdrawn_at else ("expired" if r.expires_at <= utcnow() else "active")
            print(f"{r.version:24} {r.id}  {state:9} key={r.key_id} expires={r.expires_at:%Y-%m-%d} "
                  f"platforms={','.join(f'{a.os}/{a.arch}' for a in r.artifacts)}")
        if not rels:
            print("No agent releases imported.")
    return 0


def agent_release_check(args: argparse.Namespace) -> int:
    """Check GitHub Releases for a new signed agent release and import it (same checks as an upload)."""
    from .services import agent_update_auto

    with db.get_session() as s:
        res = agent_update_auto.check_github(s, actor=args.actor)
        auth.audit(s, "agent_release_check_requested", actor_email=args.actor, status=res["status"],
                   message=res["message"][:500])
        s.commit()
    print(f"{res['status']}: {res['message']}")
    return 0 if res["status"] != "error" else 1


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python -m app.cli", description="CloudSecurity CNAPP admin CLI")
    sub = p.add_subparsers(dest="command", required=True)
    c = sub.add_parser("create-user", help="create a user (prompts for the password)")
    c.add_argument("--email", required=True)
    c.add_argument("--name", default="")
    c.add_argument("--role", choices=ROLES, default="viewer")
    c.add_argument("--password-stdin", action="store_true", help="read the password from stdin")
    c.set_defaults(func=create_user)
    r = sub.add_parser("reset-password", help="set a new password, unlock and reactivate a user")
    r.add_argument("--email", required=True)
    r.add_argument("--password-stdin", action="store_true", help="read the password from stdin")
    r.set_defaults(func=reset_password)
    f = sub.add_parser("reset-mfa", help="remove a user's authenticator app and recovery codes, unlock them")
    f.add_argument("--email", required=True)
    f.set_defaults(func=reset_mfa)
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
    ac = sub.add_parser("agent-release-check",
                        help="check GitHub Releases for a new signed agent release and import it")
    ac.add_argument("--actor", default="cli", help="name recorded in the audit log")
    ac.set_defaults(func=agent_release_check)
    args = p.parse_args(argv)
    if args.func is migrate:
        db.init_engine(config.settings.database_url, migrate=True)
    else:
        db.init_engine(config.settings.database_url)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
