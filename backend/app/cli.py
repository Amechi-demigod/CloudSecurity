"""Admin CLI.

    python -m app.cli create-user --email you@example.com --role admin [--name "Your Name"]
    python -m app.cli reset-password --email you@example.com

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
    args = p.parse_args(argv)
    db.init_engine(config.settings.database_url)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
