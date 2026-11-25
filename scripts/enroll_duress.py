#!/usr/bin/env python3
"""One-time enrollment utility for duress credentials.

Enrolls the real password and duress password into .vault/credentials.db.
"""

from __future__ import annotations

from getpass import getpass
from pathlib import Path
import sys

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from argus.duress import DuressStore


def main() -> None:
    creds_path = Path(".vault/credentials.db")
    store = DuressStore(creds_path)
    try:
        if store.has("duress"):
            sys.stdout.write("Duress already enrolled. Overwrite? [y/N]: ")
            sys.stdout.flush()
            ans = sys.stdin.readline().strip()
            if ans.lower() != "y":
                print("Enrollment aborted.")
                return

        real = getpass("Real password: ")
        if not real:
            print("Password cannot be empty.")
            return
        duress = getpass("Duress password: ")
        if not duress:
            print("Password cannot be empty.")
            return
        if real == duress:
            print("Refusing enrollment: duress password must differ from real password.")
            return

        store.set_password("real", real)
        store.set_password("duress", duress)
        print("Credentials enrolled in .vault/credentials.db.")
    finally:
        store.close()


if __name__ == "__main__":
    main()
