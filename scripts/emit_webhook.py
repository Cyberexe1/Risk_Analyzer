"""Signed payment-event emitter -- the stand-in for a payment provider.

WHY THIS EXISTS
---------------
Razorpay Test Mode requires a business account, which this project does not have.
So the provider's *sender* is simulated here. Everything the server does with the
event is real: HMAC-SHA256 verification over the raw body, replay protection,
scoring, persistence, and IP flagging.

The events below match Razorpay's documented webhook shape (`payment.captured` /
`payment.failed`, amount in paise, `notes` for merchant-supplied fields), so
pointing the server at the real provider is a secret and a URL rather than a
rewrite.

USAGE
-----
    # one successful payment
    python scripts/emit_webhook.py

    # one declined payment
    python scripts/emit_webhook.py --status failed

    # card-testing burst: 4 declines from one address, flags the IP
    python scripts/emit_webhook.py --burst 4

    # prove the endpoint rejects a forged signature
    python scripts/emit_webhook.py --forge

    # prove replay protection
    python scripts/emit_webhook.py --replay

    # full demo sequence
    python scripts/emit_webhook.py --demo

The backend must be running with FRAUDSHIELD_WEBHOOK_SECRET set to the same value
this script reads, otherwise every request is correctly refused with 401.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import sys
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load_env(path: Path = ROOT / ".env") -> None:
    """Same precedence rule as backend.py: the real environment wins."""
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        k, v = k.strip(), v.strip()
        if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
            v = v[1:-1]
        if k and k not in os.environ:
            os.environ[k] = v


def build_event(
    *,
    status: str,
    amount_rupees: float,
    method: str,
    email: str,
    device_fp: str,
    ip_hash: str,
) -> dict:
    """Provider-shaped event.

    `amount` is in PAISE, as a real provider sends it. `device_fp` and `ip_hash`
    ride in `notes` because a webhook arrives from the provider's servers, not the
    payer's browser -- the merchant has to forward them at order-creation time or
    those signals are simply unavailable for the transaction.
    """
    pid = f"pay_{uuid.uuid4().hex[:14]}"
    return {
        "id": f"evt_{uuid.uuid4().hex[:14]}",
        "entity": "event",
        "event": f"payment.{status}",
        "contains": ["payment"],
        "created_at": int(time.time()),
        "payload": {
            "payment": {
                "entity": {
                    "id": pid,
                    "entity": "payment",
                    "amount": int(round(amount_rupees * 100)),
                    "currency": "INR",
                    "status": status,
                    "method": method,
                    "captured": status == "captured",
                    "email": email,
                    "contact": "+919876543210",
                    "notes": {"device_fp": device_fp, "ip_hash": ip_hash},
                    "created_at": int(time.time()),
                }
            }
        },
    }


def send(url: str, body: dict, secret: str, *, forge: bool = False) -> tuple[int, dict | str]:
    """Sign the exact bytes we send. Signing a re-serialised copy is the classic
    bug: key order and spacing change the digest and the signature stops matching.
    """
    raw = json.dumps(body).encode("utf-8")
    signature = (
        "0" * 64 if forge
        else hmac.new(secret.encode("utf-8"), raw, hashlib.sha256).hexdigest()
    )
    req = urllib.request.Request(
        url,
        data=raw,
        method="POST",
        headers={
            "content-type": "application/json",
            "x-razorpay-signature": signature,
            "x-razorpay-event-id": body["id"],
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        payload = e.read().decode(errors="replace")
        try:
            return e.code, json.loads(payload)
        except json.JSONDecodeError:
            return e.code, payload
    except urllib.error.URLError as e:
        print(f"\ncannot reach {url}: {e.reason}")
        print("start the backend first:")
        print('  python -m uvicorn backend:app --port 8000 --forwarded-allow-ips=""')
        raise SystemExit(1) from None


def line(status: int, body: dict | str, label: str = "") -> None:
    if isinstance(body, dict):
        if body.get("ingested"):
            detail = (f"score {body.get('risk_score')} -> {body.get('decision')}"
                      f"  {body.get('transaction_id')}")
        elif body.get("duplicate"):
            detail = "DUPLICATE -- replay refused, nothing scored"
        elif "detail" in body:
            detail = str(body["detail"])
        else:
            detail = "not ingested (event type not modelled)"
    else:
        detail = str(body)[:90]
    print(f"  HTTP {status}  {label:<22} {detail}")


def main() -> None:
    load_env()
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--url", default="http://127.0.0.1:8000/v1/webhooks/payment")
    p.add_argument("--status", choices=["captured", "failed"], default="captured")
    p.add_argument("--amount", type=float, default=2499.0, help="rupees")
    p.add_argument("--method", default="card",
                   choices=["card", "upi", "netbanking", "wallet", "emi", "cod"])
    p.add_argument("--email", default="payer@example.com")
    p.add_argument("--device", default=None)
    p.add_argument("--ip", default=None)
    p.add_argument("--burst", type=int, metavar="N",
                   help="send N declines from one address to trip the IP flag")
    p.add_argument("--forge", action="store_true",
                   help="send a deliberately invalid signature; expect 401")
    p.add_argument("--replay", action="store_true",
                   help="send the same event twice; expect the second to dedupe")
    p.add_argument("--demo", action="store_true",
                   help="run the full sequence: accept, forge, replay, burst")
    a = p.parse_args()

    secret = os.environ.get("FRAUDSHIELD_WEBHOOK_SECRET", "")
    if not secret:
        print("FRAUDSHIELD_WEBHOOK_SECRET is not set.")
        print("Set it in .env (and restart the backend) so both sides share it.")
        raise SystemExit(1)

    device = a.device or f"dev_sim_{uuid.uuid4().hex[:8]}"
    ip = a.ip or f"ip_sim_{uuid.uuid4().hex[:8]}"

    if a.demo:
        print("\n1. valid signature, successful payment")
        ev = build_event(status="captured", amount_rupees=a.amount, method=a.method,
                         email=a.email, device_fp=device, ip_hash=ip)
        line(*send(a.url, ev, secret), "accepted")

        print("\n2. forged signature -- must be refused")
        ev2 = build_event(status="captured", amount_rupees=a.amount, method=a.method,
                          email=a.email, device_fp=device, ip_hash=ip)
        line(*send(a.url, ev2, secret, forge=True), "forged")

        print("\n3. replay of a valid event -- must be deduplicated")
        ev3 = build_event(status="captured", amount_rupees=a.amount, method=a.method,
                          email=a.email, device_fp=device, ip_hash=ip)
        line(*send(a.url, ev3, secret), "first delivery")
        line(*send(a.url, ev3, secret), "redelivery")

        print(f"\n4. card-testing burst from one address ({ip})")
        for i in range(4):
            evb = build_event(status="failed", amount_rupees=a.amount,
                              method=a.method, email=f"burst{i}@example.com",
                              device_fp=f"dev_burst_{i}", ip_hash=ip)
            line(*send(a.url, evb, secret), f"decline {i + 1}")
        print("\n   check the console: Suspicious IPs should now list this address.")
        print("   http://localhost:5173/admin\n")
        return

    if a.forge:
        ev = build_event(status=a.status, amount_rupees=a.amount, method=a.method,
                         email=a.email, device_fp=device, ip_hash=ip)
        line(*send(a.url, ev, secret, forge=True), "forged")
        return

    if a.replay:
        ev = build_event(status=a.status, amount_rupees=a.amount, method=a.method,
                         email=a.email, device_fp=device, ip_hash=ip)
        line(*send(a.url, ev, secret), "first delivery")
        line(*send(a.url, ev, secret), "redelivery")
        return

    if a.burst:
        print(f"sending {a.burst} declines from {ip}")
        for i in range(a.burst):
            ev = build_event(status="failed", amount_rupees=a.amount,
                             method=a.method, email=f"burst{i}@example.com",
                             device_fp=f"dev_burst_{i}", ip_hash=ip)
            line(*send(a.url, ev, secret), f"decline {i + 1}")
        return

    ev = build_event(status=a.status, amount_rupees=a.amount, method=a.method,
                     email=a.email, device_fp=device, ip_hash=ip)
    line(*send(a.url, ev, secret), a.status)


if __name__ == "__main__":
    sys.exit(main())
