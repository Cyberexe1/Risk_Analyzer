"""
FraudShield scoring API.

    uvicorn app.main:app --port 8000
    curl http://localhost:8000/health

SECURITY -- read this before exposing the service
-------------------------------------------------
Endpoints here are guarded by a single shared API key (`FRAUDSHIELD_API_KEY`).
That is NOT the auth model docs/ARCHITECTURE.md specifies, which is JWT access +
refresh tokens with Argon2id credentials in DynamoDB and per-route role gating.
None of that is built yet. Concretely, what is missing:

  - no per-user identity, so nothing distinguishes one caller from another
  - no roles, so there is no analyst/admin separation
  - no rate limiting on any endpoint
  - the review queue lives in process memory and is lost on restart

Do not run this on a public interface. It binds localhost by default and should
stay there until the auth layer exists.

The store is in-memory (app/store.py). The DynamoDB adapter is unbuilt, so state
does not survive a restart.
"""

from __future__ import annotations

import os
import secrets
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException, status
from pydantic import BaseModel, Field

from app.scorer import Scorer
from app.store import InMemoryStore

_ROOT = Path(__file__).resolve().parents[1]

API_KEY = os.environ.get("FRAUDSHIELD_API_KEY", "")
WARM_ROWS = int(os.environ.get("FRAUDSHIELD_WARM_ROWS", "40000"))

STATE: dict = {"store": None, "scorer": None, "queue": [], "txns": {}}


def _warm_store(store: InMemoryStore, limit: int) -> int:
    """Replay historical traffic so device/IP/velocity counters are populated.

    Without this every request arrives at a cold graph and looks like a brand-new
    entity, which is exactly the situation the network layer cannot score. Only
    the TRAIN split is replayed -- warming from validation or test would leak the
    evaluation period into the serving state.
    """
    csv = _ROOT / "ml" / "data" / "transactions.csv"
    if not csv.exists():
        return 0
    import pandas as pd

    df = pd.read_csv(csv)
    df = df[df.split == "train"].sort_values("ts_epoch")
    if limit:
        df = df.tail(limit)
    for r in df.groupby("customer_id", sort=False).head(1).itertuples():
        store.register_customer(r.customer_id, float(r.account_created_at))
    for r in df.itertuples():
        dt = datetime.fromtimestamp(float(r.ts_epoch), tz=timezone.utc)
        store.commit({
            "customer_id": r.customer_id, "ts": float(r.ts_epoch),
            "amount": float(r.amount), "payment_method": r.payment_method,
            "device_fp": r.device_fp, "ip_hash": r.ip_hash, "status": r.status,
            "hour": dt.hour + dt.minute / 60.0,
        })
    return len(df)


@asynccontextmanager
async def lifespan(app: FastAPI):
    store = InMemoryStore()
    n = _warm_store(store, WARM_ROWS)
    scorer = Scorer()
    STATE["store"] = store
    STATE["scorer"] = scorer
    print(f"warmed store with {n:,} historical transactions")
    print(f"model: {'DEGRADED (no artifact)' if scorer.degraded else scorer.model_version}")
    if not API_KEY:
        print("WARNING: FRAUDSHIELD_API_KEY is unset -- all endpoints are open. "
              "Set it before exposing this service anywhere.")
    yield
    STATE.clear()


app = FastAPI(
    title="FraudShield",
    description="Defense-only transaction risk scoring. Returns a decision and "
                "evidence, never a fraud verdict.",
    version="0.3.0",
    lifespan=lifespan,
)


def require_key(x_api_key: str = Header(default="")) -> None:
    if not API_KEY:
        return  # open mode, warned about at startup
    if not secrets.compare_digest(x_api_key, API_KEY):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid or missing API key")


# ---------------------------------------------------------------------------
# schemas
# ---------------------------------------------------------------------------


class ScoreRequest(BaseModel):
    customer_id: str
    amount: float = Field(gt=0)
    payment_method: str
    device_fp: str
    ip_hash: str
    ts: float | None = Field(default=None, description="epoch seconds; defaults to now")
    status: str = Field(default="success", pattern="^(success|failed)$")
    commit: bool = Field(
        default=True,
        description="apply this transaction to entity state after scoring",
    )


class SubScores(BaseModel):
    ml: float
    rules: float
    network: float


class ScoreResponse(BaseModel):
    transaction_id: str
    risk_score: float
    decision: str
    sub_scores: SubScores
    reason_codes: list
    override: str | None
    model_version: str
    degraded: bool
    scored_at: str
    latency_ms: float


class CustomerView(BaseModel):
    """Allow-list projection. A customer must never see a score, a sub-score or a
    reason code -- telling an attacker which signal fired is free reconnaissance."""

    order_id: str
    status: str
    message: str


class OutcomeRequest(BaseModel):
    label: str = Field(pattern="^(fraud|legitimate)$")
    analyst_id: str = "unknown"


# ---------------------------------------------------------------------------
# routes
# ---------------------------------------------------------------------------


@app.get("/health")
def health() -> dict:
    s: Scorer = STATE["scorer"]
    return {
        "status": "ok",
        "model_loaded": s is not None and not s.degraded,
        "model_version": s.model_version if s else None,
        "thresholds": {"review": s.review_t, "block": s.block_t} if s else None,
        "store": "in-memory (DynamoDB adapter not built)",
        "auth": "api-key" if API_KEY else "OPEN -- set FRAUDSHIELD_API_KEY",
    }


@app.post("/v1/risk/score", response_model=ScoreResponse,
          dependencies=[Depends(require_key)])
def score(req: ScoreRequest) -> ScoreResponse:
    """Analyst-facing scoring. Full evidence."""
    import time

    store: InMemoryStore = STATE["store"]
    scorer: Scorer = STATE["scorer"]
    ts = req.ts if req.ts is not None else datetime.now(timezone.utc).timestamp()
    txn = {
        "customer_id": req.customer_id, "ts": ts, "amount": req.amount,
        "payment_method": req.payment_method, "device_fp": req.device_fp,
        "ip_hash": req.ip_hash,
    }

    t0 = time.perf_counter()
    try:
        d, raw = scorer.score(store, txn)
    except Exception as exc:  # noqa: BLE001
        # Fail to a human, never silently allow. Failing open would make the
        # engine bypassable by inducing errors; failing closed would kill
        # legitimate checkout.
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"decision": "MANUAL_REVIEW", "reason": "SCORING_UNAVAILABLE",
                    "error": type(exc).__name__},
        ) from exc
    latency = (time.perf_counter() - t0) * 1000

    txn_id = f"pay_{uuid.uuid4().hex[:10]}"

    # Read-before-write: features were read above, state is applied only now.
    if req.commit:
        dt = datetime.fromtimestamp(ts, tz=timezone.utc)
        store.commit({**txn, "status": req.status,
                      "hour": dt.hour + dt.minute / 60.0})

    record = {
        "transaction_id": txn_id, "customer_id": req.customer_id,
        "amount": req.amount, "risk_score": d.risk_score, "decision": d.decision,
        "sub_scores": d.sub_scores, "reason_codes": d.reason_codes,
        "fired_rules": d.fired_rules, "override": d.override,
        "features": raw, "scored_at": datetime.now(timezone.utc).isoformat(),
        "label": None,
    }
    STATE["txns"][txn_id] = record
    if d.decision in ("MANUAL_REVIEW", "BLOCK"):
        STATE["queue"].append(txn_id)

    return ScoreResponse(
        transaction_id=txn_id, risk_score=d.risk_score, decision=d.decision,
        sub_scores=SubScores(**d.sub_scores), reason_codes=d.reason_codes,
        override=d.override, model_version=d.model_version, degraded=d.degraded,
        scored_at=record["scored_at"], latency_ms=round(latency, 2),
    )


@app.post("/v1/checkout", response_model=CustomerView,
          dependencies=[Depends(require_key)])
def checkout(req: ScoreRequest) -> CustomerView:
    """Customer-facing. Same scoring, deliberately impoverished response."""
    res = score(req)
    msg = {
        "ALLOW": ("confirmed", "Order confirmed."),
        "MANUAL_REVIEW": ("verifying",
                          "We're verifying your payment. This usually takes about "
                          "2 minutes."),
        "BLOCK": ("declined",
                  "We couldn't process this payment. Please try a different method "
                  "or contact support."),
    }[res.decision]
    return CustomerView(order_id=res.transaction_id, status=msg[0], message=msg[1])


@app.get("/v1/admin/queue", dependencies=[Depends(require_key)])
def queue(limit: int = 50) -> dict:
    items = [STATE["txns"][t] for t in STATE["queue"]]
    items.sort(key=lambda r: -r["risk_score"])
    return {
        "count": len(items),
        "items": [
            {k: v for k, v in r.items() if k != "features"} for r in items[:limit]
        ],
    }


@app.get("/v1/admin/transactions/{txn_id}", dependencies=[Depends(require_key)])
def detail(txn_id: str) -> dict:
    r = STATE["txns"].get(txn_id)
    if r is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "unknown transaction")
    return r


@app.post("/v1/admin/transactions/{txn_id}/outcome",
          dependencies=[Depends(require_key)])
def outcome(txn_id: str, req: OutcomeRequest) -> dict:
    """Record ground truth. This is the only place a fraud LABEL is created --
    the risk score never becomes a label on its own."""
    r = STATE["txns"].get(txn_id)
    if r is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "unknown transaction")
    r["label"] = req.label
    r["labelled_by"] = req.analyst_id
    r["labelled_at"] = datetime.now(timezone.utc).isoformat()
    if txn_id in STATE["queue"]:
        STATE["queue"].remove(txn_id)
    return {"transaction_id": txn_id, "label": req.label,
            "note": "label recorded for retraining; score was not a verdict"}
