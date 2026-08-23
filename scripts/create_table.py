"""
Create the FraudShield DynamoDB table. Idempotent.

    python scripts/create_table.py            # create if absent
    python scripts/create_table.py --check    # report only, no writes

Single table, PK + SK, PAY_PER_REQUEST. Holds users, refresh tokens, orders,
returns and the review queue -- see docs/ARCHITECTURE.md section 3 for the item
shapes.

WHAT THIS COSTS: on-demand billing means you pay per request, not per hour. At
demo volume that is fractions of a rupee. It is still a persistent resource in
your AWS account, so this is a deliberate script rather than something the
backend does at startup.

WHAT THIS DOES NOT CREATE: the three GSIs in ARCHITECTURE.md section 3. They
serve admin queries (queue by decision, history by device, history by IP) that
currently run from process memory. Each GSI is billed separately, so they are
left out until something actually reads them.

IAM: the principal needs CreateTable, DescribeTable and UpdateTimeToLive for this
script, then only GetItem/PutItem/UpdateItem/DeleteItem/Query at runtime. Scope
the runtime policy to this table's ARN, not "*".
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load_env() -> None:
    f = ROOT / ".env"
    if not f.exists():
        return
    for line in f.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip())


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--check", action="store_true", help="report only, create nothing")
    a = p.parse_args()

    load_env()
    import boto3
    from botocore.exceptions import ClientError

    table = os.environ.get("FRAUDSHIELD_USERS_TABLE", "fraudshield")
    region = os.environ.get("FRAUDSHIELD_AWS_REGION", "ap-south-1")
    ak = os.environ.get("AWS_ACCESS_KEY_ID") or os.environ.get("access_key")
    sk = os.environ.get("AWS_SECRET_ACCESS_KEY") or os.environ.get("secret_key")

    kw = {"region_name": region}
    if ak and sk:
        kw["aws_access_key_id"] = ak
        kw["aws_secret_access_key"] = sk
    c = boto3.client("dynamodb", **kw)

    print(f"region {region}  table {table!r}")

    try:
        d = c.describe_table(TableName=table)["Table"]
        print(f"  exists: status={d['TableStatus']} items={d.get('ItemCount', 0)}")
        print("  nothing to do")
        return 0
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            print(f"  describe failed: {e.response['Error']['Code']}", file=sys.stderr)
            return 1

    if a.check:
        print("  does not exist (--check, not creating)")
        return 0

    print("  creating (PAY_PER_REQUEST)...")
    c.create_table(
        TableName=table,
        AttributeDefinitions=[
            {"AttributeName": "PK", "AttributeType": "S"},
            {"AttributeName": "SK", "AttributeType": "S"},
        ],
        KeySchema=[
            {"AttributeName": "PK", "KeyType": "HASH"},
            {"AttributeName": "SK", "KeyType": "RANGE"},
        ],
        BillingMode="PAY_PER_REQUEST",
        Tags=[
            {"Key": "app", "Value": "fraudshield"},
            {"Key": "managed-by", "Value": "scripts/create_table.py"},
        ],
    )

    c.get_waiter("table_exists").wait(TableName=table)
    print("  ACTIVE")

    # Expiring refresh tokens and short-window counters automatically is cheaper
    # and more reliable than a scheduled cleanup job.
    for attempt in range(6):
        try:
            c.update_time_to_live(
                TableName=table,
                TimeToLiveSpecification={"Enabled": True, "AttributeName": "ttl"},
            )
            print("  TTL enabled on 'ttl'")
            break
        except ClientError as e:
            if attempt == 5:
                print(f"  TTL not enabled ({e.response['Error']['Code']}); "
                      "set it manually in the console", file=sys.stderr)
            else:
                time.sleep(3)

    print("\nnext: set FRAUDSHIELD_USERS_BACKEND=dynamodb in .env and restart the "
          "backend.\nAccounts will then survive a restart.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
