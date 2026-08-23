"""
Grant a role to an existing account.

    python scripts/grant_role.py analyst@example.com analyst

There is deliberately NO API endpoint for this. Any route that can hand out an
admin role is a privilege-escalation path, and self-service signup always
produces a `customer`. Promotion is an out-of-band act, performed by someone with
access to the user store.

IMPORTANT with the default in-memory store: the backend holds users in its own
process, so this script cannot reach them. It only works against
FRAUDSHIELD_USERS_BACKEND=dynamodb. For a local demo, use --print-sql to see what
to run, or create the analyst through the API and promote it after switching to
DynamoDB.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

# Load .env BEFORE importing backend: backend reads USERS_BACKEND and the AWS
# credentials at import time, so a late load leaves it pointed at the in-memory
# store and this script silently reports the wrong thing.
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
    p.add_argument("role", choices=backend.ROLES)
    a = p.parse_args()

    if backend.USERS_BACKEND != "dynamodb":
        print(
            "FRAUDSHIELD_USERS_BACKEND is not 'dynamodb'.\n"
            "\n"
            "The default user store lives inside the running backend process, so\n"
            "this script has no way to reach it. Options:\n"
            "\n"
            "  1. Set FRAUDSHIELD_USERS_BACKEND=dynamodb in .env, create the table\n"
            "     (see DynamoUserStore's docstring in backend.py), then rerun this.\n"
            "\n"
            "  2. For a throwaway local demo, set FRAUDSHIELD_DEV_SEED_STAFF=1 before\n"
            "     starting the backend. It seeds one analyst account and prints the\n"
            "     generated password. Never enable that outside local development.\n",
            file=sys.stderr,
        )
        return 2

    store = backend.DynamoUserStore()
    u = store.get_by_email(a.email)
    if u is None:
        print(f"No account for {a.email!r}.", file=sys.stderr)
        return 1

    store._t.update_item(  # noqa: SLF001  (deliberate: admin tooling)
        Key={"PK": f"USER#{u.user_id}", "SK": "PROFILE"},
        UpdateExpression="SET #r = :r",
        ExpressionAttributeNames={"#r": "role"},
        ExpressionAttributeValues={":r": a.role},
    )
    # Existing sessions still carry the OLD role in their access token until it
    # expires (15 min). Revoking the refresh family forces a fresh login and a
    # correctly-scoped token.
    store.revoke_family(u.user_id)
    print(f"{a.email} is now '{a.role}'. Existing sessions were revoked.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
