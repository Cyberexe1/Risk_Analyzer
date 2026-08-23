"""
Build the 22 documented features for ONE transaction from store state.

Deliberately an independent implementation of what ml/generate_dataset.py does in
its forward pass. Sharing the code would make the parity test vacuous -- the point
is to prove two independent paths agree, which is what tells us the offline metrics
describe something shippable.

Read order is the whole discipline here: every value comes from state as it stands
BEFORE this transaction is applied. `store.commit()` is called afterwards, by the
caller, never from inside this module.
"""

from __future__ import annotations

from datetime import datetime, timezone

from app.store import InMemoryStore

# Same fallback the generator uses for a customer with no history. A production
# scorer faces exactly this cold-start gap, so the model must see the same
# sentinel it was trained on rather than a quietly imputed per-customer value.
GLOBAL_AMOUNT_PRIOR = 1500.0

NO_PRIOR_TXN_GAP = 999999.0


def build(store: InMemoryStore, txn: dict) -> dict:
    """Return the 22 raw features for `txn` given current state.

    txn requires: customer_id, ts (epoch), amount, payment_method, device_fp,
    ip_hash.
    """
    cid = txn["customer_id"]
    ts = float(txn["ts"])
    dev = txn["device_fp"]
    ipa = txn["ip_hash"]
    amount = float(txn["amount"])
    method = txn["payment_method"]

    c = store.customer(cid)
    if c.first_seen is None:
        c.first_seen = ts

    dt = datetime.fromtimestamp(ts, tz=timezone.utc)
    hour = dt.hour + dt.minute / 60.0

    n_prev = c.n_txn
    prior_avg = (c.sum_amount / n_prev) if n_prev else GLOBAL_AMOUNT_PRIOR

    v10, v1h, f10, f1h = store.velocity(cid, ts)

    d = store.device(dev)
    p = store.ip(ipa)

    return {
        # transaction (4)
        "amount": round(amount, 2),
        "payment_method": method,
        "transaction_hour": dt.hour,
        "is_weekend": int(dt.weekday() >= 5),
        # velocity (4)
        "txn_count_10m": v10,
        "txn_count_1h": v1h,
        "failed_count_10m": f10,
        "failed_count_1h": f1h,
        # customer baseline (5)
        "account_age_hours": round(store.account_age_hours(cid, ts), 3),
        "customer_avg_amount": round(prior_avg, 2),
        "amount_ratio": round(min(50.0, amount / max(1.0, prior_avg)), 4),
        "prev_txn_count": n_prev,
        "historical_failure_rate": round((c.n_fail + 1) / (n_prev + 2), 4),
        # device / ip (5)
        "device_account_count": len(d.accounts),
        "device_txn_count": d.n_txn,
        "device_failure_rate": round((d.n_fail + 1) / (d.n_txn + 2), 4),
        "ip_account_count": len(p.accounts),
        "ip_txn_count": p.n_txn,
        # behavioural (4)
        "is_new_device": int(dev not in c.devices),
        "is_new_payment_method": int(method not in c.methods),
        "seconds_since_last_txn": round(
            ts - c.last_ts if c.last_ts is not None else NO_PRIOR_TXN_GAP, 1
        ),
        "hour_deviation": round(c.hour.deviation(hour), 4),
    }
