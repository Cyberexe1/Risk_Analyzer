"""Throwaway: run the demo scenario against the real scorer and print actuals."""
import os
import sys
import uuid

os.environ["FRAUDSHIELD_USERS_BACKEND"] = "memory"
os.environ["FRAUDSHIELD_DEV_SEED_STAFF"] = "0"
os.environ["FRAUDSHIELD_JWT_SECRET"] = "probe-secret"
os.environ["FRAUDSHIELD_IP_PEPPER"] = "probe-pepper"
os.environ["FRAUDSHIELD_DEMO_MODE"] = "true"
os.environ["FRAUDSHIELD_PAYMENT_PROVIDER"] = "simulated"
os.environ["FRAUDSHIELD_WARM_ROWS"] = sys.argv[1] if len(sys.argv) > 1 else "0"
os.environ.pop("FRAUDSHIELD_API_KEY", None)

from fastapi.testclient import TestClient  # noqa: E402

import backend  # noqa: E402

records = backend.InMemoryRecordStore()
users = backend.InMemoryUserStore()
backend.make_record_store = lambda: (records, "probe")
backend.make_user_store = lambda: (users, "probe")
backend.USERS_BACKEND = "memory"
backend.API_KEY = ""

PW = "probe-password-11223344"

with TestClient(backend.app) as c:
    email = f"adm-{uuid.uuid4().hex[:6]}@example.com"
    r = c.post("/v1/auth/register", json={"email": email, "password": PW})
    h = {"authorization": f"Bearer {r.json()['access_token']}"}
    backend.STATE["users"].get_by_email(email).role = "admin"

    print("thresholds:", backend.STATE["scorer"].review_t,
          backend.STATE["scorer"].block_t,
          "degraded:", backend.STATE["scorer"].degraded)

    res = c.post("/v1/admin/demo/fraud-attack", headers=h)
    print("HTTP", res.status_code)
    body = res.json()
    if res.status_code != 201:
        print(body)
        raise SystemExit(1)

    print(f"{'#':>2} {'amount':>9} {'method':<11} {'settle':<8} "
          f"{'v10m':>4} {'ratio':>7} {'ml':>6} {'rul':>5} {'net':>5} "
          f"{'score':>6} {'decision':<14} rules")
    for r_ in body["results"]:
        s = r_["sub_scores"]
        print(f"{r_['attempt']:>2} {r_['amount']:>9.0f} {r_['payment_method']:<11} "
              f"{r_['settlement']:<8} {r_['txn_count_10m']:>4} "
              f"{r_['amount_ratio']:>7.2f} {s['ml']:>6.1f} {s['rules']:>5.1f} "
              f"{s['network']:>5.1f} {r_['risk_score']:>6.1f} "
              f"{r_['decision']:<14} {','.join(r_['fired_rules'])}")

    print()
    print("signals union    :", body["signals"])
    print("decisions        :", body["decisions"])
    print("final            :", body["final_transaction"]["risk_score"],
          body["final_transaction"]["decision"])
    print("evidence         :", body["evidence"])
    print("persisted        :", body["transactions_persisted"])
    print("queued           :", body["queued_for_review"])
    print("ip_flagged       :", body["ip_flagged"])
    print("notifications    :", body["notifications"], body["email_provider"],
          "alerts_enabled:", body["alerts_enabled"])
    print("audit_events     :", body["audit_events"])
    print("baseline         :", body["baseline"]["average_amount"],
          body["baseline"]["transactions"])

    q = c.get("/v1/admin/queue", headers=h).json()
    print("queue count      :", q["count"])

    print()
    print("--- second run (same device, new customer) ---")
    b2 = c.post("/v1/admin/demo/fraud-attack", headers=h).json()
    print("final            :", b2["final_transaction"]["risk_score"],
          b2["final_transaction"]["decision"])
    print("signals union    :", b2["signals"])
    print("evidence         :", b2["evidence"])
    print("queue count      :", c.get("/v1/admin/queue", headers=h).json()["count"])
    print("distinct customers:", len({r["customer_id"] for r in
                                      backend.STATE["txns"].values()}))

    a = c.get("/v1/admin/audit?limit=200", headers=h).json()
    kinds = {}
    for e in a["entries"]:
        kinds[e["action"]] = kinds.get(e["action"], 0) + 1
    print("audit actions    :", kinds)
    demo_marked = [e for e in a["entries"] if (e.get("after") or {}).get("demo")]
    print("demo-marked      :", len(demo_marked), "of", len(a["entries"]))
    gt = [e for e in a["entries"] if (e.get("after") or {}).get("is_ground_truth")]
    print("ground truth     :", len(gt))
    trig = [e for e in a["entries"] if e["action"] == "DEMO_ATTACK_TRIGGERED"]
    print("trigger actor    :", trig[0]["actor"], trig[0].get("actor_identity"))
