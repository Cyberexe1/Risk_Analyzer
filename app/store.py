"""
Entity state store: the counters an online scorer reads before scoring.

This is the part that decides whether the whole no-lookahead design is real. The
offline pipeline computes features in one chronological pass over a sorted file.
Production has no sorted file -- it has one transaction and whatever counters were
left behind by earlier traffic. If those two paths disagree, every metric in
docs/EVALUATION.md describes a model that cannot ship.

`tests/test_parity.py` replays the generated dataset through this store and asserts
the resulting features match the offline CSV exactly.

Backends
--------
InMemoryStore   fully implemented and verified by the parity test.
DynamoDBStore   not built yet. The mapping to the single-table schema in
                docs/ARCHITECTURE.md is straightforward (see the note at the
                bottom of this file) but bucketed velocity windows are an
                approximation, so it needs its own parity run before it is
                trusted. Writing it unverified would be worse than not writing it.
"""

from __future__ import annotations

import math
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Protocol


class RunningHour:
    """Circular running mean of hour-of-day plus mean absolute deviation.

    Byte-for-byte the same update rule as ml/generate_dataset.py. The MAD is
    accumulated against a moving mean rather than recomputed, which is what an
    online scorer can actually afford.
    """

    __slots__ = ("s", "c", "n", "mad")

    def __init__(self) -> None:
        self.s = 0.0
        self.c = 0.0
        self.n = 0
        self.mad = 0.0

    def mean_hour(self) -> float:
        if self.n == 0:
            return 12.0
        ang = math.atan2(self.s / self.n, self.c / self.n)
        return (ang * 24 / (2 * math.pi)) % 24.0

    def deviation(self, hour: float) -> float:
        if self.n < 5:
            return 0.0
        d = abs(hour - self.mean_hour())
        d = min(d, 24 - d)
        return d / max(1.0, self.mad)

    def update(self, hour: float) -> None:
        d = abs(hour - self.mean_hour())
        d = min(d, 24 - d)
        ang = hour * 2 * math.pi / 24
        self.s += math.sin(ang)
        self.c += math.cos(ang)
        self.n += 1
        self.mad += (d - self.mad) / self.n


@dataclass
class CustomerState:
    created_at: float | None = None
    first_seen: float | None = None
    n_txn: int = 0
    n_fail: int = 0
    sum_amount: float = 0.0
    last_ts: float | None = None
    devices: set[str] = field(default_factory=set)
    methods: set[str] = field(default_factory=set)
    hour: RunningHour = field(default_factory=RunningHour)
    attempts: deque = field(default_factory=deque)      # timestamps
    failures: deque = field(default_factory=deque)
    method_hist: deque = field(default_factory=deque)   # (ts, method) for rules
    recent: deque = field(default_factory=deque)        # 24h activity, graph term


@dataclass
class DeviceState:
    accounts: set[str] = field(default_factory=set)
    n_txn: int = 0
    n_fail: int = 0


@dataclass
class IPState:
    accounts: set[str] = field(default_factory=set)
    n_txn: int = 0


class Store(Protocol):
    def customer(self, cid: str) -> CustomerState: ...
    def device(self, fp: str) -> DeviceState: ...
    def ip(self, h: str) -> IPState: ...
    def commit(self, ev: dict) -> None: ...


class InMemoryStore:
    """Reference implementation. Exact velocity windows via deques.

    Not a toy: this is what the parity test runs against, and it is the backend
    the API uses until the DynamoDB adapter is verified.
    """

    def __init__(self) -> None:
        self._cust: dict[str, CustomerState] = defaultdict(CustomerState)
        self._dev: dict[str, DeviceState] = defaultdict(DeviceState)
        self._ip: dict[str, IPState] = defaultdict(IPState)
        # adjacency for the network layer
        self.acct_devices: dict[str, set[str]] = defaultdict(set)
        self.acct_ips: dict[str, set[str]] = defaultdict(set)

    def customer(self, cid: str) -> CustomerState:
        return self._cust[cid]

    def device(self, fp: str) -> DeviceState:
        return self._dev[fp]

    def ip(self, h: str) -> IPState:
        return self._ip[h]

    def register_customer(self, cid: str, created_at: float) -> None:
        """Called when an account is created. In production this is the signup
        write, so `created_at` is known rather than inferred."""
        c = self._cust[cid]
        if c.created_at is None:
            c.created_at = created_at

    def account_age_hours(self, cid: str, now: float) -> float:
        c = self._cust[cid]
        base = c.created_at if c.created_at is not None else c.first_seen
        if base is None:
            base = now
        return max(0.0, (now - base) / 3600.0)

    # ---- trailing-window helpers -------------------------------------------
    @staticmethod
    def _trim(dq: deque, now: float, window: float) -> int:
        while dq and now - dq[0] > window:
            dq.popleft()
        return len(dq)

    def velocity(self, cid: str, now: float) -> tuple[int, int, int, int]:
        """(attempts_10m, attempts_1h, failures_10m, failures_1h).

        One deque per series, trimmed to the LONGEST window (1h) and counted
        within the shorter one. Trimming to 600s would silently destroy the
        1h count -- the offline pass kept separate deques per window, so this
        has to preserve the same semantics from shared storage.
        """
        c = self._cust[cid]
        n_att_1h = self._trim(c.attempts, now, 3600)
        n_fail_1h = self._trim(c.failures, now, 3600)
        return (
            self._count(c.attempts, now, 600),
            n_att_1h,
            self._count(c.failures, now, 600),
            n_fail_1h,
        )

    @staticmethod
    def _count(dq: deque, now: float, window: float) -> int:
        return sum(1 for t in dq if now - t <= window)

    def methods_last_hour(self, cid: str, now: float) -> int:
        c = self._cust[cid]
        while c.method_hist and now - c.method_hist[0][0] > 3600:
            c.method_hist.popleft()
        return len({m for _, m in c.method_hist})

    # ---- write path --------------------------------------------------------
    def commit(self, ev: dict) -> None:
        """Apply a scored transaction to state. MUST be called only after
        features have been read, mirroring the offline forward pass."""
        cid, ts = ev["customer_id"], ev["ts"]
        dev, ipa = ev["device_fp"], ev["ip_hash"]
        failed = ev["status"] == "failed"
        hour = ev["hour"]

        c = self._cust[cid]
        c.n_txn += 1
        c.sum_amount += ev["amount"]
        if failed:
            c.n_fail += 1
        c.last_ts = ts
        c.devices.add(dev)
        c.methods.add(ev["payment_method"])
        c.hour.update(hour)
        c.attempts.append(ts)
        if failed:
            c.failures.append(ts)
        c.method_hist.append((ts, ev["payment_method"]))
        c.recent.append(ts)

        d = self._dev[dev]
        d.accounts.add(cid)
        d.n_txn += 1
        if failed:
            d.n_fail += 1

        p = self._ip[ipa]
        p.accounts.add(cid)
        p.n_txn += 1

        self.acct_devices[cid].add(dev)
        self.acct_ips[cid].add(ipa)

    # ---- graph reads -------------------------------------------------------
    def device_accounts(self, fp: str) -> set[str]:
        return self._dev[fp].accounts

    def ip_accounts(self, h: str) -> set[str]:
        return self._ip[h].accounts

    def account_activity_24h(self, cid: str, now: float) -> int:
        c = self._cust[cid]
        while c.recent and now - c.recent[0] > 86400:
            c.recent.popleft()
        return len(c.recent)

    def account_totals(self, cid: str) -> tuple[int, int]:
        c = self._cust[cid]
        return c.n_txn, c.n_fail


# ---------------------------------------------------------------------------
# DynamoDB mapping, for when the adapter is built
# ---------------------------------------------------------------------------
#
#   CustomerState  -> CUSTOMER#<id> / PROFILE      atomic ADD on n_txn, n_fail,
#                                                  sum_amount; SET last_ts
#   devices/methods-> string sets (SS) on the same item, ADD to append
#   RunningHour    -> s, c, n, mad as numbers on the profile item; all four
#                     update with ADD except mad, which needs the read value.
#                     That makes the hour update non-atomic -- acceptable, since
#                     hour_deviation ranks 10th by gain and a lost update costs
#                     almost nothing.
#   attempts/fails -> CUSTOMER#<id> / WINDOW#10M#<epoch//600> with TTL, ADD on
#                     count. NOTE: bucketed counts are an APPROXIMATION of the
#                     exact deque. A transaction at t sees buckets, not a true
#                     trailing 600s. This is the one place the online path will
#                     legitimately diverge from the offline pipeline, and it needs
#                     its own parity measurement before it is trusted.
#   DeviceState    -> DEVICE#<fp> / COUNTERS  + DEVICE#<fp> / ACCT#<cid> edges
#   IPState        -> IP#<hash> / COUNTERS    + IP#<hash> / ACCT#<cid> edges
#
# The whole commit() body becomes one TransactWriteItems call, so the transaction
# record and its counters land together or not at all.
