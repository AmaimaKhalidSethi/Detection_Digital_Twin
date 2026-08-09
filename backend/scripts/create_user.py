"""Controlled local bootstrap for Detection Digital Twin users.

Run from backend: ``python -m scripts.create_user admin@example.internal``.
The password is read from the terminal and is never printed or stored plaintext.
"""
from __future__ import annotations

import argparse
import getpass

from app.core.auth import create_user
from app.models.db import init_db, make_engine, make_session_factory


def main() -> None:
    parser = argparse.ArgumentParser(description="Create a Detection Digital Twin user")
    parser.add_argument("username", help="Internal email address or username")
    parser.add_argument("--role", choices=("admin", "analyst"), default="analyst")
    args = parser.parse_args()
    password = getpass.getpass("Password (12+ characters): ")
    confirmation = getpass.getpass("Confirm password: ")
    if password != confirmation:
        raise SystemExit("Passwords do not match")
    engine = make_engine()
    init_db(engine)
    session = make_session_factory(engine)()
    try:
        user = create_user(session, username=args.username, password=password, role=args.role)
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc
    finally:
        session.close()
    print(f"Created {user.role} user: {user.username}")


if __name__ == "__main__":
    main()
