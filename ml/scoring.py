"""
The non-ML scoring layers: deterministic rules, the entity-graph network score,
the aggregator, and the MVP hand-picked formula kept as a baseline.

Everything here is computed in a single chronological forward pass, same as the
feature generator. A network score that peeked at future edges would be leakage
just as surely as a lookahead feature.
"""

from __future__ import annotations

import math
from collections import defaultdict, deque

import numpy as np
import pandas as pd

# ---------------------------------------------------------------------------
# Rule layer
# ---------------------------------------------------------------------------

RULE_POINTS = {
    "velocity_breach": 20,
    "device_abuse": 15,
    "ip_concentration": 10,
    "amount_anomaly": 15,
    "failure_spike": 10,
    "new_account": 5,
    "new_device": 5,
    "method_switching": 10,
}

# Correlated rules are grouped and only the highest scorer in each group counts.
# device_abuse and ip_concentration both measure "one actor, many accounts"; adding
# them punishes the same evidence twice. This is the structural fix for the
# additive blow-up problem in the original hand-picked formula.
RULE_GROUPS = {
    "entity_sharing": ["device_abuse", "ip_concentration"],
    "velocity": ["velocity_breach", "failure_spike", "method_switching"],
    "novelty": ["new_account", "new_device"],
    "amount": ["amount_anomaly"],
}

RULE_REASONS = {
    "velocity_breach": "{txn_count_10m:.0f} attempts in 10 minutes",
    "device_abuse": "Device linked to {device_account_count:.0f} accounts",
    "ip_concentration": "{ip_account_count:.0f} accounts on this IP",
    "amount_anomaly": "Amount {amount_ratio:.1f}x customer baseline",
    "failure_spike": "{failed_count_1h:.0f} failures in the last hour",
    "new_account": "Account created {account_age_hours:.0f} hours ago",
    "new_device": "First transaction from this device",
    "method_switching": "{methods_1h:.0f} payment methods in an hour",
}


def methods_per_hour(df: pd.DataFrame) -> np.ndarray:
    """Distinct payment methods used by this customer in the trailing hour.

    A rule input, not a model feature -- which is why it is computed here rather
    than in the generator. Keeps the documented feature count at 22.
    """
    out = np.zeros(len(df), dtype=np.int16)
    hist: dict[str, deque] = defaultdict(deque)
    cids = df["customer_id"].to_numpy()
    ts = df["ts_epoch"].to_numpy(dtype=float)
    methods = df["payment_method"].astype(str).to_numpy()
    for i in range(len(df)):
        dq = hist[cids[i]]
        while dq and ts[i] - dq[0][0] > 3600:
            dq.popleft()
        out[i] = len({m for _, m in dq})
        dq.append((ts[i], methods[i]))
    return out


def rule_scores(df: pd.DataFrame, methods_1h: np.ndarray) -> tuple[np.ndarray, list[list[str]]]:
    fired_cols = {
        "velocity_breach": df["txn_count_10m"].to_numpy() > 5,
        "device_abuse": df["device_account_count"].to_numpy() > 4,
        "ip_concentration": df["ip_account_count"].to_numpy() > 6,
        "amount_anomaly": df["amount_ratio"].to_numpy() > 4,
        "failure_spike": df["failed_count_1h"].to_numpy() > 5,
        "new_account": df["account_age_hours"].to_numpy() < 24,
        "new_device": df["is_new_device"].to_numpy() == 1,
        "method_switching": methods_1h > 3,
    }

    n = len(df)
    score = np.zeros(n, dtype=float)
    for members in RULE_GROUPS.values():
        # max points among fired members of this group
        best = np.zeros(n, dtype=float)
        for r in members:
            best = np.maximum(best, np.where(fired_cols[r], RULE_POINTS[r], 0))
        score += best
    score = np.minimum(score, 100.0)

    fired = [[] for _ in range(n)]
    for r, mask in fired_cols.items():
        for i in np.flatnonzero(mask):
            fired[i].append(r)
    return score, fired


# ---------------------------------------------------------------------------
# Network layer
# ---------------------------------------------------------------------------

HIGH_POP_IP_ACCOUNTS = 25  # above this, an IP is treated as shared infrastructure
MAX_COMPONENT = 200


def network_scores(df: pd.DataFrame) -> np.ndarray:
    """Shared-entity graph score, built incrementally in time order.

    Approximations vs. docs/RISK_ENGINE.md, stated plainly:
      - depth-2 expansion only runs when the depth-1 component is small (<20
        accounts), to keep this O(n) on 100k rows
      - the `sync` term uses the share of component accounts active in the last
        24h instead of median pairwise time similarity
    Both make the score slightly weaker, not stronger.
    """
    dev_accts: dict[str, set] = defaultdict(set)
    ip_accts: dict[str, set] = defaultdict(set)
    acct_devs: dict[str, set] = defaultdict(set)
    acct_ips: dict[str, set] = defaultdict(set)
    acct_recent: dict[str, deque] = defaultdict(deque)
    acct_fail: dict[str, int] = defaultdict(int)
    acct_n: dict[str, int] = defaultdict(int)

    cids = df["customer_id"].to_numpy()
    devs = df["device_fp"].to_numpy()
    ips = df["ip_hash"].to_numpy()
    ts = df["ts_epoch"].to_numpy(dtype=float)
    failed = (df["status"].to_numpy() == "failed")

    out = np.zeros(len(df), dtype=float)

    for i in range(len(df)):
        cid, dev, ipa, now = cids[i], devs[i], ips[i], ts[i]

        ip_pop = len(ip_accts[ipa])
        ip_is_shared = ip_pop > HIGH_POP_IP_ACCOUNTS

        # depth 1: accounts reachable through this device or IP
        accounts = set(dev_accts[dev])
        if not ip_is_shared:
            accounts |= ip_accts[ipa]
        accounts.add(cid)

        # depth 2, only when cheap
        if len(accounts) < 20:
            for a in list(accounts):
                for d in acct_devs[a]:
                    accounts |= dev_accts[d]
                    if len(accounts) > MAX_COMPONENT:
                        break
                if len(accounts) > MAX_COMPONENT:
                    break
        if len(accounts) > MAX_COMPONENT:
            accounts = set(list(accounts)[:MAX_COMPONENT])

        n_acct = len(accounts)
        if n_acct < 3:
            out[i] = 0.0
        else:
            edges = 0
            txn24 = 0
            fails = 0
            total = 0
            active = 0
            for a in accounts:
                edges += len(acct_devs[a]) + len(acct_ips[a])
                dq = acct_recent[a]
                while dq and now - dq[0] > 86400:
                    dq.popleft()
                if dq:
                    active += 1
                txn24 += len(dq)
                fails += acct_fail[a]
                total += acct_n[a]

            size = min(1.0, math.log1p(n_acct) / math.log1p(20))
            density = min(1.0, (edges / n_acct) / 4.0)
            burst = min(1.0, txn24 / (3.0 * n_acct))
            fail = (fails / total) if total else 0.0
            sync = active / n_acct

            raw = 0.30 * size + 0.25 * density + 0.20 * burst + 0.15 * fail + 0.10 * sync

            # Damp components whose only link is high-population infrastructure.
            # Without this every customer on a large mobile carrier inherits a ring
            # score, which was the most expensive false-positive source in testing.
            penalty = 0.35 if ip_is_shared and len(dev_accts[dev]) <= 2 else 1.0
            out[i] = min(100.0, raw * 100.0 * penalty)

        # ---- apply the event to the graph (strictly after reading) ----
        dev_accts[dev].add(cid)
        ip_accts[ipa].add(cid)
        acct_devs[cid].add(dev)
        acct_ips[cid].add(ipa)
        acct_recent[cid].append(now)
        acct_n[cid] += 1
        if failed[i]:
            acct_fail[cid] += 1

    return out


# ---------------------------------------------------------------------------
# Aggregation
# ---------------------------------------------------------------------------

W_ML, W_RULES, W_NETWORK = 0.70, 0.20, 0.10


def aggregate(ml: np.ndarray, rules: np.ndarray, net: np.ndarray) -> np.ndarray:
    """Weighted mean of three bounded scores. Bounded, monotonic, explainable one
    term at a time -- unlike summing raw points, which is unbounded."""
    return np.clip(W_ML * ml + W_RULES * rules + W_NETWORK * net, 0, 100)


def apply_overrides(
    final: np.ndarray, rules: np.ndarray, net: np.ndarray, df: pd.DataFrame
) -> tuple[np.ndarray, np.ndarray]:
    """Two documented bypasses of the weighted mean. Returns (score, override_kind)
    where kind is 0=none, 1=hard block, 2=trusted floor."""
    kind = np.zeros(len(df), dtype=np.int8)

    hard = (rules >= 100) & (net > 85)
    final = np.where(hard, 100.0, final)
    kind[hard] = 1

    trusted = (
        (df["account_age_hours"].to_numpy() > 180 * 24)
        & (df["prev_txn_count"].to_numpy() > 50)
        & (df["amount_ratio"].to_numpy() < 2)
        & (rules == 0)
    )
    final = np.where(trusted, np.minimum(final, 39.0), final)
    kind[trusted & ~hard] = 2
    return final, kind


# ---------------------------------------------------------------------------
# Baseline: the original hand-picked formula
# ---------------------------------------------------------------------------


def mvp_formula(df: pd.DataFrame) -> np.ndarray:
    """The MVP's five hand-chosen weights, implemented exactly as specified:

        +25 velocity, +20 device linked to 5 accounts, +18 amount anomaly,
        +15 unusual behaviour, +13 account history

    Kept as a baseline so the value of learning the weights is measured rather
    than asserted.
    """
    s = np.zeros(len(df), dtype=float)
    s += np.where(df["txn_count_10m"].to_numpy() > 5, 25, 0)
    s += np.where(df["device_account_count"].to_numpy() >= 5, 20, 0)
    s += np.where(df["amount_ratio"].to_numpy() > 4, 18, 0)
    s += np.where(
        (df["hour_deviation"].to_numpy() > 2) | (df["is_new_device"].to_numpy() == 1), 15, 0
    )
    s += np.where(
        (df["account_age_hours"].to_numpy() < 24)
        | (df["historical_failure_rate"].to_numpy() > 0.30),
        13,
        0,
    )
    return s
