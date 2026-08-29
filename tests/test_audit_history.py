"""Audit history retrieval: dates, pagination, ordering, filters.

WHAT THIS SUITE IS ABOUT
------------------------
The audit trail was write-complete but read-limited: every day had always been
persisted to its own `AUDIT#<utc-date>` partition, and the endpoint only ever
queried today's. An analyst could not answer "what happened yesterday?".

The properties defended here:

  * **History is reachable.** A date, or a bounded range, newest day first.
  * **Reads are bounded.** Explicit `limit`, clamped; keyset pagination; one
    partition at a time; never a scan.
  * **Order is deterministic.** Sorted on the stored sort key, never on dict
    insertion order, and stable when timestamps collide.
  * **A partial answer never looks complete.** If one day in a range fails, the
    range is not reported as complete.
  * **The cursor is opaque and cannot escape its range.**

Both stores are exercised: InMemoryRecordStore and the real DynamoRecordStore
driven by the existing FakeTable. No AWS, no network.

Run:  python -m pytest tests/test_audit_history.py -v
"""
from __future__ import annotations

import base64
import itertools
import os
import sys
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

os.environ["FRAUDSHIELD_USERS_BACKEND"] = "memory"
os.environ["FRAUDSHIELD_WARM_ROWS"] = "0"
os.environ["FRAUDSHIELD_DEV_SEED_STAFF"] = "0"
os.environ["FRAUDSHIELD_JWT_SECRET"] = "test-only-jwt-secret-audit-history"
os.environ["FRAUDSHIELD_IP_PEPPER"] = "test-only-pepper-audit-history"
os.environ.pop("FRAUDSHIELD_API_KEY", None)

from fastapi.testclient import TestClient  # noqa: E402

import backend  # noqa: E402

PW = "audit-history-password-3319"

TODAY = datetime.now(timezone.utc).date()
D_TODAY = TODAY.isoformat()
D_YESTERDAY = (TODAY - timedelta(days=1)).isoformat()
D_OLDER = (TODAY - timedelta(days=2)).isoformat()


# ---------------------------------------------------------------------------
# stores
# ---------------------------------------------------------------------------

class FakeTable:
    """Minimal boto3 Table stand-in, including Limit / ExclusiveStartKey /
    LastEvaluatedKey -- which is what makes the Dynamo pagination path real."""

    def __init__(self):
        self.items: dict[tuple[str, str], dict] = {}
        self.queries = 0

    def put_item(self, Item):  # noqa: N803
        self.items[(Item["PK"], Item["SK"])] = dict(Item)

    def get_item(self, Key):  # noqa: N803
        it = self.items.get((Key["PK"], Key["SK"]))
        return {"Item": dict(it)} if it else {}

    def query(self, KeyConditionExpression, ExpressionAttributeValues,  # noqa: N803
              ScanIndexForward=True, Limit=None,  # noqa: N803
              ExclusiveStartKey=None):  # noqa: N803
        self.queries += 1
        pk = ExpressionAttributeValues[":p"]
        prefix = ExpressionAttributeValues.get(":s")
        rows = [dict(v) for (p, s), v in self.items.items()
                if p == pk and (prefix is None or s.startswith(prefix))]
        rows.sort(key=lambda r: r["SK"], reverse=not ScanIndexForward)
        if ExclusiveStartKey is not None:
            start = ExclusiveStartKey["SK"]
            rows = [r for r in rows
                    if (r["SK"] < start if not ScanIndexForward
                        else r["SK"] > start)]
        out = {"Items": rows}
        if Limit is not None and len(rows) > Limit:
            out["Items"] = rows[:Limit]
            out["LastEvaluatedKey"] = {"PK": pk, "SK": rows[Limit - 1]["SK"]}
        return out

    def update_item(self, Key, UpdateExpression,  # noqa: N803
                    ExpressionAttributeNames, ExpressionAttributeValues):  # noqa: N803
        it = self.items.get((Key["PK"], Key["SK"]))
        if it is None:
            return
        for placeholder, name in ExpressionAttributeNames.items():
            it[name] = ExpressionAttributeValues[":v" + placeholder[2:]]


def dynamo_store() -> backend.DynamoRecordStore:
    s = object.__new__(backend.DynamoRecordStore)
    s._t = FakeTable()
    return s


@pytest.fixture(params=["memory", "dynamo"])
def store(request):
    """Every retrieval test runs against BOTH stores.

    Parity is the point: an analyst must see the same history whichever store is
    configured, and the paging code paths are genuinely different -- memory slices
    a sorted list, Dynamo uses Limit + ExclusiveStartKey.
    """
    return (backend.InMemoryRecordStore() if request.param == "memory"
            else dynamo_store())


@pytest.fixture
def db(store, monkeypatch):
    users = backend.InMemoryUserStore()
    monkeypatch.setattr(backend, "USERS_BACKEND", "memory")
    monkeypatch.setattr(backend, "make_record_store", lambda: (store, "test"))
    monkeypatch.setattr(backend, "make_user_store", lambda: (users, "test"))
    monkeypatch.setattr(backend, "API_KEY", "")
    return store


@contextmanager
def app_run():
    with TestClient(backend.app) as c:
        yield c


def register(c, email: str) -> dict:
    r = c.post("/v1/auth/register", json={"email": email, "password": PW})
    assert r.status_code == 201, r.text
    return {"authorization": f"Bearer {r.json()['access_token']}"}


def admin(c, tag: str = "adm") -> dict:
    email = f"{tag}-{uuid.uuid4().hex[:8]}@example.com"
    h = register(c, email)
    backend.STATE["users"].get_by_email(email).role = "admin"
    return h


_seed_batch = itertools.count()


def seed(store, day: str, n: int, *, action="RISK_DECISION",
         actor="system:scorer", before=None, second=0,
         batch: int | None = None) -> list[str]:
    """Write n audit items straight into a date partition.

    Written directly rather than through real traffic so a test can place events
    on a PAST date -- audit() always stamps 'now', and back-dating the clock would
    be a far more invasive fixture.

    `second` fixes the seconds field so identical timestamps can be forced.

    Each CALL gets its own batch number woven into the sort key. Without it a
    second seed() on the same day reuses the same timestamps and event ids and
    silently overwrites the first -- which is exactly what happened while writing
    these tests and produced four confusing failures.
    """
    # `batch` is pinned by the parity test, which must write byte-identical
    # content into two different stores.
    batch = next(_seed_batch) if batch is None else batch
    ids = []
    for i in range(n):
        eid = f"evt_{day}_b{batch:03d}_{i:04d}"
        ts = (f"{day}T10:00:{second:02d}.{batch:06d}+00:00" if second else
              f"{day}T{10 + batch % 12:02d}:{i:02d}:00.{batch:06d}+00:00")
        item = {
            "event_id": eid, "action": action, "actor": actor, "at": ts,
            "before": before if before is not None else {"transaction_id": f"pay_{i:04d}"},
            "after": {"is_ground_truth": False, "seq": i},
        }
        store.put(f"AUDIT#{day}", f"{ts}#{eid}", item)
        ids.append(eid)
    return ids


def get(c, h, **params):
    q = "&".join(f"{k}={v}" for k, v in params.items() if v is not None)
    r = c.get(f"/v1/admin/audit{'?' + q if q else ''}", headers=h)
    assert r.status_code == 200, r.text
    return r.json()


# ===========================================================================
# 1. the limitation is closed
# ===========================================================================

def test_yesterday_is_retrievable(db):
    """The whole point. Previously unreachable through the API."""
    seed(db, D_YESTERDAY, 3)
    with app_run() as c:
        h = admin(c)
        got = get(c, h, date=D_YESTERDAY)

    assert got["count"] == 3
    assert got["source"] == "persistent"
    assert got["complete"] is True
    assert got["days_requested"] == [D_YESTERDAY]


def test_today_remains_the_default(db):
    """Callers that pass no date must keep working exactly as before."""
    seed(db, D_TODAY, 2)
    seed(db, D_YESTERDAY, 5)
    with app_run() as c:
        h = admin(c)
        got = get(c, h)

    assert got["count"] == 2, "the default must not silently widen to all history"
    assert got["days_requested"] == [D_TODAY]
    assert got["day"] == D_TODAY


def test_a_date_with_no_events_is_empty_not_an_error(db):
    with app_run() as c:
        h = admin(c)
        got = get(c, h, date=D_OLDER)

    assert got["count"] == 0
    assert got["entries"] == []
    assert got["source"] == "empty"
    assert got["complete"] is True
    assert got["warning"] is None


def test_a_date_range_reads_newest_day_first(db):
    seed(db, D_OLDER, 1)
    seed(db, D_YESTERDAY, 1)
    seed(db, D_TODAY, 1)
    with app_run() as c:
        h = admin(c)
        got = get(c, h, start_date=D_OLDER, end_date=D_TODAY, limit=10)

    assert got["count"] == 3
    assert got["days_requested"] == [D_TODAY, D_YESTERDAY, D_OLDER]
    # Newest event first overall.
    ats = [e["at"] for e in got["entries"]]
    assert ats == sorted(ats, reverse=True)


def test_one_sided_range_is_treated_as_a_single_day(db):
    seed(db, D_YESTERDAY, 2)
    with app_run() as c:
        h = admin(c)
        assert get(c, h, start_date=D_YESTERDAY)["count"] == 2
        assert get(c, h, end_date=D_YESTERDAY)["count"] == 2


# ===========================================================================
# 2. validation
# ===========================================================================

@pytest.mark.parametrize("bad", ["not-a-date", "2026-13-01", "2026-02-30",
                                 "29-08-2026", "2026/08/29", "today"])
def test_an_invalid_date_is_rejected(db, bad):
    with app_run() as c:
        h = admin(c)
        r = c.get(f"/v1/admin/audit?date={bad}", headers=h)
        assert r.status_code == 422, f"{bad!r} was accepted"


def test_a_blank_date_means_not_supplied(db):
    """`?date=` with no value is an absent parameter, not a malformed one, and is
    treated the same way as omitting it. Consistent with `?action=`."""
    seed(db, D_TODAY, 2)
    with app_run() as c:
        h = admin(c)
        r = c.get("/v1/admin/audit?date=", headers=h)
        assert r.status_code == 200
        assert r.json()["days_requested"] == [D_TODAY]


def test_an_inverted_range_is_rejected(db):
    with app_run() as c:
        h = admin(c)
        r = c.get(f"/v1/admin/audit?start_date={D_TODAY}&end_date={D_OLDER}",
                  headers=h)
        assert r.status_code == 422


def test_an_over_long_range_is_rejected_rather_than_served(db):
    """A range request must not be able to ask for unbounded work."""
    far = (TODAY - timedelta(days=backend.AUDIT_MAX_DAYS + 5)).isoformat()
    with app_run() as c:
        h = admin(c)
        r = c.get(f"/v1/admin/audit?start_date={far}&end_date={D_TODAY}",
                  headers=h)
        assert r.status_code == 422
        assert str(backend.AUDIT_MAX_DAYS) in r.text


def test_date_and_range_together_is_rejected(db):
    with app_run() as c:
        h = admin(c)
        r = c.get(f"/v1/admin/audit?date={D_TODAY}&start_date={D_OLDER}",
                  headers=h)
        assert r.status_code == 422


# ===========================================================================
# 3. pagination
# ===========================================================================

def test_limit_one_walks_the_whole_partition(db):
    seed(db, D_YESTERDAY, 5)
    seen: list[str] = []
    with app_run() as c:
        h = admin(c)
        cursor = None
        for _ in range(10):
            got = get(c, h, date=D_YESTERDAY, limit=1, cursor=cursor)
            assert got["count"] == 1
            assert got["limit"] == 1
            seen.append(got["entries"][0]["event_id"])
            if not got["has_more"]:
                break
            cursor = got["next_cursor"]

    assert len(seen) == 5
    assert len(set(seen)) == 5, "a page was repeated"


def test_limit_ten_returns_one_full_page_and_a_cursor(db):
    seed(db, D_YESTERDAY, 25)
    with app_run() as c:
        h = admin(c)
        first = get(c, h, date=D_YESTERDAY, limit=10)
        assert first["count"] == 10
        assert first["has_more"] is True
        assert first["next_cursor"]

        second = get(c, h, date=D_YESTERDAY, limit=10,
                     cursor=first["next_cursor"])
        assert second["count"] == 10
        third = get(c, h, date=D_YESTERDAY, limit=10,
                    cursor=second["next_cursor"])
        assert third["count"] == 5
        assert third["has_more"] is False
        assert third["next_cursor"] is None

    ids = [e["event_id"] for e in first["entries"] + second["entries"]
           + third["entries"]]
    assert len(set(ids)) == 25, "pages overlapped or skipped"


def test_the_last_page_reports_no_more(db):
    seed(db, D_YESTERDAY, 3)
    with app_run() as c:
        h = admin(c)
        got = get(c, h, date=D_YESTERDAY, limit=10)

    assert got["count"] == 3
    assert got["has_more"] is False
    assert got["next_cursor"] is None


def test_a_single_event_needs_no_cursor(db):
    seed(db, D_YESTERDAY, 1)
    with app_run() as c:
        h = admin(c)
        got = get(c, h, date=D_YESTERDAY, limit=50)

    assert got["count"] == 1
    assert got["has_more"] is False


def test_an_empty_log_reports_no_more(db):
    with app_run() as c:
        h = admin(c)
        got = get(c, h, date=D_OLDER, limit=50)

    assert got["count"] == 0
    assert got["has_more"] is False
    assert got["next_cursor"] is None


def test_pagination_crosses_a_day_boundary(db):
    seed(db, D_YESTERDAY, 3)
    seed(db, D_TODAY, 3)
    collected: list[str] = []
    days_seen: set[str] = set()
    with app_run() as c:
        h = admin(c)
        cursor = None
        for _ in range(12):
            got = get(c, h, start_date=D_YESTERDAY, end_date=D_TODAY,
                      limit=2, cursor=cursor)
            collected += [e["event_id"] for e in got["entries"]]
            days_seen.update(got["days_read"])
            if not got["has_more"]:
                break
            cursor = got["next_cursor"]

    assert len(set(collected)) == 6, f"got {collected}"
    assert {D_TODAY, D_YESTERDAY} <= days_seen


def test_limit_is_clamped_to_the_documented_maximum(db):
    seed(db, D_YESTERDAY, 3)
    with app_run() as c:
        h = admin(c)
        got = get(c, h, date=D_YESTERDAY, limit=999999)

    assert got["limit"] == backend.AUDIT_PAGE_MAX


@pytest.mark.parametrize("bad", [0, -5])
def test_a_nonsense_limit_is_clamped_up_not_rejected(db, bad):
    seed(db, D_YESTERDAY, 2)
    with app_run() as c:
        h = admin(c)
        got = get(c, h, date=D_YESTERDAY, limit=bad)
    assert got["limit"] >= 1


# ===========================================================================
# 4. the cursor
# ===========================================================================

def test_the_cursor_is_opaque_and_leaks_no_storage_internals(db):
    seed(db, D_YESTERDAY, 5)
    with app_run() as c:
        h = admin(c)
        got = get(c, h, date=D_YESTERDAY, limit=2)

    token = got["next_cursor"]
    # Not a Dynamo LastEvaluatedKey, not JSON, not a raw key.
    assert "PK" not in token and "SK" not in token
    assert "AUDIT#" not in token
    assert "{" not in token and '"' not in token


@pytest.mark.parametrize("bad", ["garbage", "!!!!", "eyJhIjoxfQ",
                                 base64.urlsafe_b64encode(b"nodelimiter").decode(),
                                 base64.urlsafe_b64encode(b"|").decode()])
def test_an_invalid_cursor_is_rejected(db, bad):
    seed(db, D_YESTERDAY, 3)
    with app_run() as c:
        h = admin(c)
        r = c.get(f"/v1/admin/audit?date={D_YESTERDAY}&cursor={bad}", headers=h)
        assert r.status_code == 422, f"{bad!r} was accepted"


def test_a_cursor_cannot_escape_the_requested_range(db):
    """The guard that makes an unsigned token safe: it can only resume inside the
    range this request asked for."""
    seed(db, D_OLDER, 3)
    forged = base64.urlsafe_b64encode(
        f"{D_OLDER}|{D_OLDER}T10:00:00.000000+00:00#evt_x".encode()
    ).decode().rstrip("=")
    with app_run() as c:
        h = admin(c)
        r = c.get(f"/v1/admin/audit?date={D_YESTERDAY}&cursor={forged}",
                  headers=h)
        assert r.status_code == 422
        assert "date range" in r.text


def test_a_cursor_from_a_range_works_within_that_range(db):
    seed(db, D_OLDER, 2)
    seed(db, D_YESTERDAY, 2)
    with app_run() as c:
        h = admin(c)
        first = get(c, h, start_date=D_OLDER, end_date=D_YESTERDAY, limit=1)
        assert first["has_more"] is True
        second = get(c, h, start_date=D_OLDER, end_date=D_YESTERDAY, limit=1,
                     cursor=first["next_cursor"])
        assert second["count"] == 1
        assert (second["entries"][0]["event_id"]
                != first["entries"][0]["event_id"])


# ===========================================================================
# 5. ordering
# ===========================================================================

def test_events_are_newest_first_within_a_partition(db):
    seed(db, D_YESTERDAY, 8)
    with app_run() as c:
        h = admin(c)
        got = get(c, h, date=D_YESTERDAY, limit=50)

    ats = [e["at"] for e in got["entries"]]
    assert ats == sorted(ats, reverse=True)


def test_identical_timestamps_still_order_deterministically(db):
    """Two events in the same microsecond must not come back in an arbitrary
    order. The sort key carries the event id, which breaks the tie."""
    seed(db, D_YESTERDAY, 6, second=30)
    with app_run() as c:
        h = admin(c)
        a = get(c, h, date=D_YESTERDAY, limit=50)
        b = get(c, h, date=D_YESTERDAY, limit=50)

    ids_a = [e["event_id"] for e in a["entries"]]
    ids_b = [e["event_id"] for e in b["entries"]]
    assert ids_a == ids_b, "repeated reads returned different orders"
    assert len(set(ids_a)) == 6
    # Deterministic AND documented: descending on the composite sort key.
    assert ids_a == sorted(ids_a, reverse=True)


def test_ordering_is_stable_across_pagination_with_tied_timestamps(db):
    seed(db, D_YESTERDAY, 6, second=30)
    walked: list[str] = []
    with app_run() as c:
        h = admin(c)
        cursor = None
        for _ in range(10):
            got = get(c, h, date=D_YESTERDAY, limit=2, cursor=cursor)
            walked += [e["event_id"] for e in got["entries"]]
            if not got["has_more"]:
                break
            cursor = got["next_cursor"]

    assert len(set(walked)) == 6, f"tied timestamps broke paging: {walked}"


def test_order_does_not_depend_on_write_order(db):
    """Insertion order must not be what makes a read look sorted. Python dicts
    preserve it, which hides an unsorted read in memory mode."""
    day = D_YESTERDAY
    for i in (4, 0, 2, 1, 3):
        ts = f"{day}T10:{i:02d}:00.000000+00:00"
        db.put(f"AUDIT#{day}", f"{ts}#evt_{i}", {
            "event_id": f"evt_{i}", "action": "RISK_DECISION",
            "actor": "system:scorer", "at": ts, "before": {}, "after": {},
        })
    with app_run() as c:
        h = admin(c)
        got = get(c, h, date=day, limit=50)

    assert [e["event_id"] for e in got["entries"]] == [
        "evt_4", "evt_3", "evt_2", "evt_1", "evt_0"]


# ===========================================================================
# 6. filters
# ===========================================================================

def test_the_action_filter_still_works_on_a_past_date(db):
    seed(db, D_YESTERDAY, 4, action="RISK_DECISION")
    seed(db, D_YESTERDAY, 2, action="OUTCOME_RECORDED",
         actor="analyst@example.com")
    with app_run() as c:
        h = admin(c)
        got = get(c, h, date=D_YESTERDAY, action="OUTCOME_RECORDED", limit=50)

    assert got["count"] == 2
    assert {e["action"] for e in got["entries"]} == {"OUTCOME_RECORDED"}
    assert got["filters"]["action"] == "OUTCOME_RECORDED"


def test_the_actor_filter_is_case_insensitive(db):
    seed(db, D_YESTERDAY, 3, action="OUTCOME_RECORDED",
         actor="analyst@example.com")
    seed(db, D_YESTERDAY, 2, action="RISK_DECISION")
    with app_run() as c:
        h = admin(c)
        got = get(c, h, date=D_YESTERDAY, actor="ANALYST@Example.com", limit=50)

    assert got["count"] == 3
    assert {e["actor"] for e in got["entries"]} == {"analyst@example.com"}


def test_the_transaction_filter_finds_one_event(db):
    seed(db, D_YESTERDAY, 6)
    with app_run() as c:
        h = admin(c)
        got = get(c, h, date=D_YESTERDAY, transaction_id="pay_0003", limit=50)

    assert got["count"] == 1
    assert got["entries"][0]["before"]["transaction_id"] == "pay_0003"


def test_a_filter_matching_nothing_returns_empty_not_an_error(db):
    seed(db, D_YESTERDAY, 4)
    with app_run() as c:
        h = admin(c)
        got = get(c, h, date=D_YESTERDAY, transaction_id="pay_nope", limit=50)

    assert got["count"] == 0
    assert got["entries"] == []
    assert got["complete"] is True


def test_a_filter_fills_a_page_rather_than_returning_a_short_one(db):
    """A filter that rejects most rows must still fill the page, or `has_more`
    means nothing."""
    seed(db, D_YESTERDAY, 30, action="RISK_DECISION")
    seed(db, D_YESTERDAY, 5, action="OUTCOME_RECORDED",
         actor="analyst@example.com")
    with app_run() as c:
        h = admin(c)
        got = get(c, h, date=D_YESTERDAY, action="OUTCOME_RECORDED", limit=5)

    assert got["count"] == 5
    assert {e["action"] for e in got["entries"]} == {"OUTCOME_RECORDED"}


def test_filters_combine(db):
    seed(db, D_YESTERDAY, 3, action="OUTCOME_RECORDED",
         actor="a@example.com", before={"transaction_id": "pay_same"})
    seed(db, D_YESTERDAY, 3, action="OUTCOME_RECORDED",
         actor="b@example.com", before={"transaction_id": "pay_same"})
    with app_run() as c:
        h = admin(c)
        got = get(c, h, date=D_YESTERDAY, action="OUTCOME_RECORDED",
                  actor="a@example.com", transaction_id="pay_same", limit=50)

    assert got["count"] == 3
    assert {e["actor"] for e in got["entries"]} == {"a@example.com"}


def test_a_filter_works_across_a_range(db):
    seed(db, D_YESTERDAY, 2, action="PROMO_OVERRIDE",
         actor="a@example.com", before={"redemption_id": "rdm_1"})
    seed(db, D_TODAY, 2, action="PROMO_OVERRIDE",
         actor="a@example.com", before={"redemption_id": "rdm_1"})
    seed(db, D_TODAY, 3, action="RISK_DECISION")
    with app_run() as c:
        h = admin(c)
        got = get(c, h, start_date=D_YESTERDAY, end_date=D_TODAY,
                  redemption_id="rdm_1", limit=50)

    assert got["count"] == 4
    assert {e["action"] for e in got["entries"]} == {"PROMO_OVERRIDE"}


# ===========================================================================
# 7. store parity and query economy
# ===========================================================================

def test_both_stores_return_the_same_page(monkeypatch):
    """Parity: an analyst must see the same history whichever store is
    configured, even though the paging code paths differ."""
    def run(store):
        # Pinned batch: both stores must receive identical items, or the
        # comparison below would be testing the fixture rather than the stores.
        seed(store, D_YESTERDAY, 12, batch=0)
        users = backend.InMemoryUserStore()
        monkeypatch.setattr(backend, "USERS_BACKEND", "memory")
        monkeypatch.setattr(backend, "make_record_store", lambda: (store, "t"))
        monkeypatch.setattr(backend, "make_user_store", lambda: (users, "t"))
        monkeypatch.setattr(backend, "API_KEY", "")
        with app_run() as c:
            h = admin(c)
            first = get(c, h, date=D_YESTERDAY, limit=5)
            second = get(c, h, date=D_YESTERDAY, limit=5,
                         cursor=first["next_cursor"])
        return first, second

    m1, m2 = run(backend.InMemoryRecordStore())
    d1, d2 = run(dynamo_store())

    assert [e["event_id"] for e in m1["entries"]] == \
        [e["event_id"] for e in d1["entries"]]
    assert [e["event_id"] for e in m2["entries"]] == \
        [e["event_id"] for e in d2["entries"]]
    assert m1["has_more"] == d1["has_more"] is True
    assert m1["count"] == d1["count"] == 5


def test_a_page_does_not_read_the_whole_partition_in_dynamo_mode(monkeypatch):
    """Bounded reads. A page must cost a page, not the partition."""
    store = dynamo_store()
    seed(store, D_YESTERDAY, 500)
    users = backend.InMemoryUserStore()
    monkeypatch.setattr(backend, "USERS_BACKEND", "memory")
    monkeypatch.setattr(backend, "make_record_store", lambda: (store, "t"))
    monkeypatch.setattr(backend, "make_user_store", lambda: (users, "t"))
    monkeypatch.setattr(backend, "API_KEY", "")

    with app_run() as c:
        h = admin(c)
        store._t.queries = 0
        got = get(c, h, date=D_YESTERDAY, limit=10)

    assert got["count"] == 10
    # One query for the page. Not 50, and certainly not one per item.
    assert store._t.queries == 1, f"{store._t.queries} queries for one page"


def test_query_prefix_follows_dynamo_paging(monkeypatch):
    """The other bug fixed here: query_prefix issued ONE query and ignored
    LastEvaluatedKey, so any partition over DynamoDB's 1 MB response cap was
    silently truncated -- no error, no warning."""
    store = dynamo_store()
    seed(store, D_YESTERDAY, 250)

    class Capped(FakeTable):
        """Forces LastEvaluatedKey after 100 items, as a real 1 MB cap would."""

        def query(self, **kw):  # noqa: N803
            kw.setdefault("Limit", None)
            if kw["Limit"] is None:
                kw["Limit"] = 100
            return super().query(**kw)

    capped = Capped()
    capped.items = store._t.items
    store._t = capped

    rows = store.query_prefix(f"AUDIT#{D_YESTERDAY}", "")
    assert len(rows) == 250, f"truncated to {len(rows)}"
    assert len({r["event_id"] for r in rows}) == 250


# ===========================================================================
# 8. persistence failure
# ===========================================================================

def test_a_failed_single_day_read_is_reported_incomplete(db, monkeypatch):
    seed(db, D_YESTERDAY, 3)

    def boom(*a, **kw):
        raise RuntimeError("simulated outage on host-db-07.internal")

    with app_run() as c:
        h = admin(c)
        monkeypatch.setattr(type(db), "query_page", boom, raising=False)
        monkeypatch.setattr(type(db), "query_prefix", boom)
        got = get(c, h, date=D_YESTERDAY)

    assert got["complete"] is False
    assert "incomplete" in got["warning"].lower()
    assert got["days_failed"] == [D_YESTERDAY]
    # No infrastructure detail.
    assert "host-db-07" not in repr(got)
    assert "RuntimeError" not in repr(got)


def test_a_partly_failed_range_is_not_reported_complete(db, monkeypatch):
    """If one day succeeds and another fails, the range is NOT complete."""
    seed(db, D_TODAY, 2)
    seed(db, D_YESTERDAY, 2)

    real_page = getattr(type(db), "query_page")

    def selective(self, pk, sk_prefix, **kw):
        if pk.endswith(D_YESTERDAY):
            raise RuntimeError("simulated partition outage")
        return real_page(self, pk, sk_prefix, **kw)

    with app_run() as c:
        h = admin(c)
        monkeypatch.setattr(type(db), "query_page", selective)
        got = get(c, h, start_date=D_YESTERDAY, end_date=D_TODAY, limit=50)

    assert got["complete"] is False
    assert got["source"] == "partial"
    assert got["days_failed"] == [D_YESTERDAY]
    assert D_YESTERDAY in got["warning"]
    # The day that worked is still served.
    assert got["count"] == 2


def test_a_healthy_read_is_reported_complete(db):
    seed(db, D_YESTERDAY, 2)
    with app_run() as c:
        h = admin(c)
        got = get(c, h, date=D_YESTERDAY)

    assert got["source"] == "persistent"
    assert got["complete"] is True
    assert got["warning"] is None
    assert got["days_failed"] == []


# ===========================================================================
# 9. projection and authorization
# ===========================================================================

def test_no_storage_keys_leak_on_any_date(db):
    seed(db, D_YESTERDAY, 3)
    seed(db, D_TODAY, 3)
    with app_run() as c:
        h = admin(c)
        for params in ({"date": D_YESTERDAY},
                       {"start_date": D_YESTERDAY, "end_date": D_TODAY},
                       {}):
            got = get(c, h, limit=50, **params)
            for e in got["entries"]:
                assert "PK" not in e and "SK" not in e
            assert "AUDIT#" not in repr(got["entries"])


def test_history_stays_admin_only(db):
    seed(db, D_YESTERDAY, 2)
    with app_run() as c:
        cust = register(c, f"c-{uuid.uuid4().hex[:8]}@example.com")
        assert c.get(f"/v1/admin/audit?date={D_YESTERDAY}",
                     headers=cust).status_code == 403
        assert c.get(f"/v1/admin/audit?date={D_YESTERDAY}"
                     ).status_code in (401, 403)

        an_email = f"an-{uuid.uuid4().hex[:8]}@example.com"
        an = register(c, an_email)
        backend.STATE["users"].get_by_email(an_email).role = "analyst"
        assert c.get(f"/v1/admin/audit?date={D_YESTERDAY}",
                     headers=an).status_code == 403

        assert c.get(f"/v1/admin/audit?date={D_YESTERDAY}",
                     headers=admin(c)).status_code == 200


def test_a_customer_cannot_reach_history_through_a_range_or_cursor(db):
    seed(db, D_YESTERDAY, 2)
    with app_run() as c:
        h = admin(c)
        cursor = get(c, h, date=D_YESTERDAY, limit=1)["next_cursor"]
        cust = register(c, f"c2-{uuid.uuid4().hex[:8]}@example.com")
        for url in (f"/v1/admin/audit?start_date={D_OLDER}&end_date={D_TODAY}",
                    f"/v1/admin/audit?date={D_YESTERDAY}&cursor={cursor}"):
            assert c.get(url, headers=cust).status_code == 403


def test_no_analyst_email_is_reachable_by_a_customer(db):
    seed(db, D_YESTERDAY, 2, action="OUTCOME_RECORDED",
         actor="analyst@fraudshield.local")
    with app_run() as c:
        cust = register(c, f"c3-{uuid.uuid4().hex[:8]}@example.com")
        r = c.get(f"/v1/admin/audit?date={D_YESTERDAY}", headers=cust)
        assert r.status_code == 403
        assert "analyst@fraudshield.local" not in r.text


# ===========================================================================
# 10. restart across two dates  (Phase 10)
# ===========================================================================

def _full_event(day: str, *, eid: str, action: str, actor: str,
                identity: dict | None, before: dict, after: dict) -> dict:
    ts = f"{day}T11:22:33.123456+00:00"
    ev = {"event_id": eid, "action": action, "actor": actor, "at": ts,
          "before": before, "after": after}
    if identity:
        ev["actor_identity"] = identity
    return ev


def test_events_on_two_dates_both_survive_a_restart(db):
    """Phase 10, end to end.

    Two human events on two different dates, a full application restart, then each
    date retrieved separately -- asserting every accountability field comes back
    unchanged. Not just "the row exists".
    """
    ident_a = {"user_id": "u_analyst_1", "email": "analyst@fraudshield.local",
               "role": "analyst"}
    ident_b = {"user_id": "u_admin_1", "email": "admin@fraudshield.local",
               "role": "admin"}

    ev_a = _full_event(
        D_OLDER, eid="out_dayA", action="OUTCOME_RECORDED",
        actor="analyst@fraudshield.local", identity=ident_a,
        before={"transaction_id": "pay_A", "order_id": "ord_A",
                "decision": "MANUAL_REVIEW", "risk_score": 63.4,
                "label": None, "settlement": "success",
                "customer_status": "verifying"},
        after={"label": "legitimate", "outcome": "MARK_LEGITIMATE",
               "ground_truth": True, "is_ground_truth": True,
               "confusion_cell": "false_positive"})
    ev_b = _full_event(
        D_YESTERDAY, eid="pov_dayB", action="PROMO_OVERRIDE",
        actor="admin@fraudshield.local", identity=ident_b,
        before={"redemption_id": "rdm_B", "decision": "HOLD",
                "status": "under_review", "label": None},
        after={"human_outcome": "OVERRIDDEN", "label": "legitimate",
               "status": "credited", "override_by": "admin@fraudshield.local",
               "override_at": f"{D_YESTERDAY}T11:22:33.123456+00:00",
               "is_ground_truth": True})

    # Written before the first run, so both dates already exist in the store.
    db.put(f"AUDIT#{D_OLDER}", f"{ev_a['at']}#{ev_a['event_id']}", ev_a)
    db.put(f"AUDIT#{D_YESTERDAY}", f"{ev_b['at']}#{ev_b['event_id']}", ev_b)

    # ---- run 1: both readable -------------------------------------------
    with app_run() as c:
        h = admin(c, "restart1")
        a1 = get(c, h, date=D_OLDER)
        b1 = get(c, h, date=D_YESTERDAY)
        assert a1["count"] == 1 and b1["count"] == 1

    assert backend.STATE == {}, "STATE must be wiped between runs"

    # ---- run 2: same store, fresh process -------------------------------
    with app_run() as c:
        h = admin(c, "restart2")
        a2 = get(c, h, date=D_OLDER)
        b2 = get(c, h, date=D_YESTERDAY)

    for label, before_restart, after_restart, expected_ident in (
            ("date A", a1, a2, ident_a), ("date B", b1, b2, ident_b)):
        assert after_restart["count"] == 1, label
        assert after_restart["source"] == "persistent", label
        assert after_restart["complete"] is True, label
        got = after_restart["entries"][0]
        was = before_restart["entries"][0]

        assert got == was, f"{label}: the event changed across the restart"
        assert got["actor_identity"] == expected_ident, label
        assert got["actor"] == expected_ident["email"], label
        # Timestamp preserved exactly, including microseconds, and belonging to
        # the partition it was read from.
        assert got["at"] == was["at"], label
        assert got["at"].endswith("+00:00"), label
        assert got["at"].startswith(after_restart["days_requested"][0]), label
        assert got["after"]["is_ground_truth"] is True, label
        assert got["before"]["label"] is None, label
        # Storage keys still absent after a round trip.
        assert "PK" not in got and "SK" not in got, label

    # The two dates are distinct partitions and do not bleed into each other.
    assert a2["entries"][0]["event_id"] == "out_dayA"
    assert b2["entries"][0]["event_id"] == "pov_dayB"
    assert a2["entries"][0]["before"]["decision"] == "MANUAL_REVIEW"
    assert a2["entries"][0]["before"]["risk_score"] == 63.4
    assert b2["entries"][0]["before"]["decision"] == "HOLD"
    assert b2["entries"][0]["after"]["override_by"] == "admin@fraudshield.local"


def test_a_range_after_restart_returns_both_dates(db):
    seed(db, D_OLDER, 2, action="OUTCOME_RECORDED", actor="a@example.com")
    seed(db, D_YESTERDAY, 3, action="PROMO_OVERRIDE", actor="b@example.com")

    with app_run() as c:
        admin(c, "rr1")

    with app_run() as c:
        h = admin(c, "rr2")
        got = get(c, h, start_date=D_OLDER, end_date=D_YESTERDAY, limit=50)

    assert got["count"] == 5
    assert got["complete"] is True
    assert set(got["days_read"]) == {D_OLDER, D_YESTERDAY}
    assert {e["action"] for e in got["entries"]} == {
        "OUTCOME_RECORDED", "PROMO_OVERRIDE"}


def test_a_real_human_action_is_retrievable_by_todays_date_after_restart(
        db, monkeypatch):
    """The other half: not hand-seeded rows, but an event this application
    actually emitted, retrieved by explicit date after a restart."""
    def fake_score(self, store, txn):
        return backend.Decision(
            risk_score=63.4, decision="MANUAL_REVIEW",
            sub_scores={"ml": 44.4, "rules": 12.7, "network": 0.0},
            reason_codes=[], fired_rules=[], override=None,
            model_version="test-model-1", degraded=False,
        ), {"amount": float(txn["amount"])}

    monkeypatch.setattr(backend.Scorer, "score", fake_score)
    card = {"number": "4111 1111 1111 1111", "expiry_month": 12,
            "expiry_year": 2029, "cvv": "123", "holder": "History Tester"}

    with app_run() as c:
        cust = register(c, f"hist-{uuid.uuid4().hex[:8]}@example.com")
        body = c.post("/v1/orders", headers=cust, json={
            "items": [{"product_id": "p10", "qty": 1}],
            "payment_method": "card", "device_fp": "dev_hist",
            "card": card}).json()
        txn_id = next(t for t, v in backend.STATE["txns"].items()
                      if v.get("order_id") == body["order_id"])
        h = admin(c, "real1")
        assert c.post(f"/v1/admin/transactions/{txn_id}/outcome", headers=h,
                      json={"label": "legitimate"}).status_code == 200

    with app_run() as c:
        h = admin(c, "real2")
        got = get(c, h, date=D_TODAY, action="OUTCOME_RECORDED",
                  transaction_id=txn_id, limit=50)

    assert got["count"] == 1
    ev = got["entries"][0]
    assert ev["actor_identity"]["role"] == "admin"
    assert ev["before"]["decision"] == "MANUAL_REVIEW"
    assert ev["before"]["risk_score"] == 63.4
    assert ev["after"]["outcome"] == "MARK_LEGITIMATE"
    assert ev["after"]["is_ground_truth"] is True
