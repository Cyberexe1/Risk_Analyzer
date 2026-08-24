"""
Delete a staff account so the startup seed can recreate it with a known password.

    python scripts/reset_staff.py admin@fraudshield.local

The seed never overwrites an existing account -- silently resetting someone's
password on every restart would be worse than the inconvenience. So changing a
seeded password is a two-step act: remove the account, restart the backend.

Removes the profile, the email-uniqueness index item, and every refresh token, so
any live session for that account dies with it.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

_envf = ROOT / ".env"
if _envf.exists():
    for _line in _envf.read_text(encoding="utf-8").splitlines():
        _line = _line.strip()
        if _line and not _line.startswith("#") and "=" in _line:
            _k, _v = _line.split("=", 1)
            os.environ.setdefault(_k.strip(), _v.strip())

import backend  # noqa: E402


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("email")
    a = p.parse_args()
    email = a.email.strip().lower()

    if backend.USERS_BACKEND != "dynamodb":
        print("FRAUDSHIELD_USERS_BACKEND is not 'dynamodb'. The in-memory store "
              "lives inside the running backend, so just restart it.",
              file=sys.stderr)
        return 2

    store = backend.DynamoUserStore()
    u = store.get_by_email(email)
    if u is None:
        print(f"No account for {email!r}. Nothing to do.")
        return 0

    store.revoke_family(u.user_id)
    store._t.delete_item(Key={"PK": f"USER#{u.user_id}", "SK": "PROFILE"})  # noqa: SLF001
    store._t.delete_item(Key={"PK": f"EMAIL#{email}", "SK": "USER"})        # noqa: SLF001
    print(f"Deleted {email} (role was {u.role!r}) and revoked its sessions.")
    print("Restart the backend with FRAUDSHIELD_DEV_SEED_STAFF=1 to recreate it.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
