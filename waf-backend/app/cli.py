"""Admin account commands. The password is typed privately, or read from WAF_NEW_ADMIN_PASSWORD.

  py -m app.cli create-admin --username sara
  py -m app.cli reset-password --username admin
  py -m app.cli delete-admin --username sara
"""
from __future__ import annotations

import argparse
import getpass
import os
import sys

from sqlalchemy import delete, select

from .db import session_scope
from .models import AdminUser
from .security.auth import MIN_PASSWORD_LENGTH, hash_password


def _new_password() -> str:
    password = os.environ.get("WAF_NEW_ADMIN_PASSWORD") or getpass.getpass("New password: ")
    if len(password) < MIN_PASSWORD_LENGTH:
        sys.exit(f"The password must have at least {MIN_PASSWORD_LENGTH} characters.")
    return password


def main() -> None:
    parser = argparse.ArgumentParser(description="Manage WAF admin accounts")
    parser.add_argument("command", choices=("create-admin", "reset-password", "delete-admin"))
    parser.add_argument("--username", required=True)
    args = parser.parse_args()

    with session_scope() as session:
        user = session.scalar(select(AdminUser).where(AdminUser.username == args.username))
        if args.command == "create-admin":
            if user:
                sys.exit("That username already exists.")
            session.add(AdminUser(username=args.username, password_hash=hash_password(_new_password())))
        elif not user:
            sys.exit("No admin has that username.")
        elif args.command == "reset-password":
            user.password_hash = hash_password(_new_password())
            user.token_version += 1
            user.failed_attempts = 0
            user.locked_until = None
        else:
            session.execute(delete(AdminUser).where(AdminUser.username == args.username))
    print(f"Done: {args.command} for {args.username}")


if __name__ == "__main__":
    main()
