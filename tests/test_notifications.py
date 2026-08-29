"""Analyst email notification tests.

THE THREE PROPERTIES THAT MATTER MOST
-------------------------------------
1. **Email can never affect a risk decision.** A BLOCK blocks, a MANUAL_REVIEW
   reaches the queue, and the audit trail is written, whether or not the mail
   transport works. Several tests below break email deliberately and assert the
   decision survives intact.

2. **A burst is one alert, not forty.** Card testing produces a run of declines
   from one address. Without deduplication the analyst gets a mailbox they mute,
   which is functionally the same as having no alerting at all.

3. **No credential ever leaves the process.** The SMTP password must not appear
   in a log line, an API response, an audit record, a repr, or a traceback.

Also asserted: ALLOW alerts nobody, a customer never learns an alert happened,
and delivering an email is never mistaken for a human having reviewed anything.

No SMTP server is contacted. The transport is injected in every SMTP test.

Run:  python -m pytest tests/test_notifications.py -v
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import smtplib
import ssl
import sys
import time
import uuid
from contextlib import contextmanager
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

WEBHOOK_SECRET = "test-only-webhook-secret-notifications"
os.environ["FRAUDSHIELD_USERS_BACKEND"] = "memory"
os.environ["FRAUDSHIELD_WARM_ROWS"] = "0"
os.environ["FRAUDSHIELD_DEV_SEED_STAFF"] = "0"
os.environ["FRAUDSHIELD_JWT_SECRET"] = "test-only-jwt-secret-notifications"
os.environ["FRAUDSHIELD_IP_PEPPER"] = "test-only-pepper-notifications"
os.environ["FRAUDSHIELD_WEBHOOK_SECRET"] = WEBHOOK_SECRET
os.environ.pop("FRAUDSHIELD_API_KEY", None)

from fastapi.testclient import TestClient  # noqa: E402

import backend  # noqa: E402
import notifications as nf  # noqa: E402

PW = "notification-test-password-2871"
CARD = {"number": "4111 1111 1111 1111", "expiry_month": 12,
        "expiry_year": 2029, "cvv": "123", "holder": "Notify Tester"}

P_ALLOW = ("p1", 2499.0)
P_REVIEW = ("p10", 27499.0)
P_BLOCK = ("p3", 42999.0)

RECIPIENTS = "analyst@fraudshield.local, admin@fraudshield.local"

# A value that must never appear anywhere observable.
SECRET_PW = "SMTP-PASSWORD-MUST-NEVER-APPEAR-9f3a2b"


# ---------------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------------

def _decision_for(amount: float) -> backend.Decision:
    if amount >= 40000:
        decision, score = "BLOCK", 91.4
    elif amount >= 20000:
        decision, score = "MANUAL_REVIEW", 41.5
    else:
        decision, score = "ALLOW", 3.1
    return backend.Decision(
        risk_score=score, decision=decision,
        sub_scores={"ml": score * 0.7, "rules": score * 0.2, "network": 0.0},
        reason_codes=[{"code": "VELOCITY_10M", "severity": "high",
                       "detail": "7 attempts in 10 minutes", "source": "rule"}],
        fired_rules=["velocity_burst"], override=None,
        model_version="test-model-1", degraded=False,
    )


@pytest.fixture
def pinned_scorer(monkeypatch):
    """Pin the decision by amount. Weights, thresholds and rules untouched."""
    def fake_score(self, store, txn):
        return _decision_for(float(txn["amount"])), {"amount": float(txn["amount"])}

    monkeypatch.setattr(backend.Scorer, "score", fake_score)


@pytest.fixture
def db(monkeypatch):
    records = backend.InMemoryRecordStore()
    users = backend.InMemoryUserStore()
    monkeypatch.setattr(backend, "USERS_BACKEND", "memory")
    monkeypatch.setattr(backend, "make_record_store",
                        lambda: (records, "memory:notif-test"))
    monkeypatch.setattr(backend, "make_user_store",
                        lambda: (users, "memory:notif-test"))
    monkeypatch.setattr(backend, "API_KEY", "")
    monkeypatch.setattr(backend, "WEBHOOK_SECRET", WEBHOOK_SECRET)
    # Recipients configured, console provider. `_EMAIL_CFG` is bound at import,
    # so it is patched on the module rather than in os.environ.
    monkeypatch.setattr(backend, "_EMAIL_CFG", {
        "requested": "console", "sender": "alerts@fraudshield.local",
        "recipients_raw": RECIPIENTS, "host": "", "port": 587,
        "username": "", "password": "", "use_tls": True,
        "console_url": "http://localhost:5173",
    })
    return records


@contextmanager
def app_run():
    with TestClient(backend.app) as c:
        yield c


def register(c, email: str) -> dict:
    r = c.post("/v1/auth/register", json={"email": email, "password": PW})
    assert r.status_code == 201, r.text
    return {"authorization": f"Bearer {r.json()['access_token']}"}


def staff(c, tag: str, role: str = "admin") -> dict:
    email = f"{tag}-{uuid.uuid4().hex[:8]}@example.com"
    h = register(c, email)
    backend.STATE["users"].get_by_email(email).role = role
    return h


def order(c, headers, product):
    r = c.post("/v1/orders", headers=headers, json={
        "items": [{"product_id": product[0], "qty": 1}],
        "payment_method": "card", "device_fp": "dev_notify", "card": CARD,
    })
    assert r.status_code == 201, r.text
    return r.json()


def sent_messages() -> list:
    return backend.STATE["email_provider"].sent


def notif_records() -> list[dict]:
    return backend.STATE.get("notifications") or []


def audit_actions() -> set[str]:
    return {e["action"] for e in backend.STATE["audit"]}


def signed_event(*, status="failed", amount_paise=249900, ip_hash="ip_wh_notify"):
    pid = f"pay_{uuid.uuid4().hex[:12]}"
    eid = f"evt_{uuid.uuid4().hex[:12]}"
    body = {
        "id": eid, "entity": "event", "event": f"payment.{status}",
        "created_at": time.time(),
        "payload": {"payment": {"entity": {
            "id": pid, "amount": amount_paise, "currency": "INR",
            "status": status, "method": "card",
            "email": f"payer-{uuid.uuid4().hex[:6]}@example.com",
            "contact": "+919876543210",
            "notes": {"device_fp": "dev_wh_notify", "ip_hash": ip_hash},
        }}},
    }
    raw = json.dumps(body).encode()
    sig = hmac.new(WEBHOOK_SECRET.encode(), raw, hashlib.sha256).hexdigest()
    return raw, sig, eid


class FakeTransport:
    def __init__(self, raises=None):
        self.raises = raises
        self.calls: list[tuple] = []

    def send_message(self, msg, sender, recipients):
        self.calls.append((msg, sender, tuple(recipients)))
        if self.raises is not None:
            raise self.raises


def smtp(transport=None, **kw):
    base = dict(host="smtp.example.com", port=587, username="u@example.com",
                password=SECRET_PW, sender="alerts@example.com", use_tls=True)
    base.update(kw)
    return nf.SMTPEmailProvider(transport=transport, **base)


class ExplodingProvider:
    provider_name = "exploding"

    def is_configured(self):
        return True

    def send_email(self, **kw):
        raise RuntimeError("transport exploded")


class FailingProvider:
    provider_name = "failing"

    def __init__(self):
        self.calls = 0
        self.sent: list = []

    def is_configured(self):
        return True

    def send_email(self, **kw):
        self.calls += 1
        return nf.SendResult(provider=self.provider_name,
                             status=nf.STATUS_FAILED, recipient_count=2,
                             error="SMTP delivery failed (auth_failed)",
                             error_category="auth_failed")


# ===========================================================================
# 1. provider: console
# ===========================================================================

def test_console_provider_records_the_message_it_would_have_sent():
    p = nf.ConsoleEmailProvider(echo=False)
    res = p.send_email(to=["a@x.com", "b@x.com"], subject="S", body="B",
                       metadata={"event_type": "BLOCK"})
    assert res.ok and res.status == nf.STATUS_SENT
    assert res.recipient_count == 2
    assert res.provider == "console"
    assert len(p.sent) == 1
    assert p.sent[0].to == ("a@x.com", "b@x.com")
    assert p.sent[0].subject == "S"
    assert p.sent[0].body == "B"
    assert p.sent[0].event_type == "BLOCK"


def test_console_provider_needs_no_credentials():
    """The default must work on a fresh clone with nothing configured."""
    assert nf.ConsoleEmailProvider().is_configured() is True


def test_console_provider_says_it_did_not_transmit():
    """`status: sent` means the provider did its job -- rendering. The banner and
    the provider name must stop anyone reading that as delivery."""
    p = nf.ConsoleEmailProvider(echo=False)
    p.send_email(to=["a@x.com"], subject="S", body="B")
    banner = nf.ConsoleEmailProvider.render(p.sent[0])
    assert "NOT transmitted" in banner
    assert p.provider_name == "console"


def test_console_provider_echoes_a_demo_banner(capsys):
    p = nf.ConsoleEmailProvider(echo=True)
    p.send_email(to=["analyst@fraudshield.local"],
                 subject="[FraudShield] Transaction requires review - pay_123",
                 body="Risk Score: 41.5")
    out = capsys.readouterr().out
    assert "FraudShield EMAIL ALERT" in out
    assert "analyst@fraudshield.local" in out
    assert "pay_123" in out
    assert "Risk Score: 41.5" in out


def test_console_sink_is_inspectable_and_clearable():
    p = nf.ConsoleEmailProvider(echo=False)
    p.send_email(to=["a@x.com"], subject="1", body="b")
    p.send_email(to=["a@x.com"], subject="2", body="b")
    assert [m.subject for m in p.sent] == ["1", "2"]
    p.clear()
    assert p.sent == []


# ===========================================================================
# 2. provider: SMTP
# ===========================================================================

def test_smtp_is_configured_needs_host_and_sender():
    assert smtp().is_configured() is True
    assert nf.SMTPEmailProvider(host="", sender="a@x.com").is_configured() is False
    assert nf.SMTPEmailProvider(host="h", sender="").is_configured() is False


def test_smtp_does_not_require_credentials_for_an_internal_relay():
    """An unauthenticated relay on a trusted network is legitimate. Demanding a
    username would force an operator to invent one."""
    p = nf.SMTPEmailProvider(host="relay.internal", sender="a@x.com")
    assert p.is_configured() is True
    assert p.missing() == []


def test_smtp_missing_configuration_is_named_for_the_operator():
    assert nf.SMTPEmailProvider().missing() == [
        "FRAUDSHIELD_SMTP_HOST", "FRAUDSHIELD_ALERT_FROM"]


def test_smtp_sends_a_well_formed_message():
    t = FakeTransport()
    res = smtp(t).send_email(to=["a@x.com", "b@x.com"], subject="Subj",
                             body="Body", metadata={"event_type": "BLOCK"})
    assert res.ok
    assert res.recipient_count == 2
    msg, sender, recips = t.calls[0]
    assert sender == "alerts@example.com"
    assert recips == ("a@x.com", "b@x.com")
    assert msg["Subject"] == "Subj"
    assert msg["To"] == "a@x.com, b@x.com"
    assert msg["X-FraudShield-Event"] == "BLOCK"
    # Marked as automation so mailing lists do not auto-reply to alerts.
    assert msg["Auto-Submitted"] == "auto-generated"
    assert msg.get_content().strip() == "Body"


def test_smtp_unconfigured_reports_failure_without_touching_the_network():
    res = nf.SMTPEmailProvider().send_email(to=["a@x.com"], subject="s", body="b")
    assert res.status == nf.STATUS_FAILED
    assert res.error_category == "not_configured"
    assert "FRAUDSHIELD_SMTP_HOST" in res.error


def test_smtp_with_no_recipients_is_skipped_not_failed():
    """No recipients configured is an operator choice, not a delivery failure.
    Calling it a failure would bury real failures in noise."""
    res = smtp(FakeTransport()).send_email(to=[], subject="s", body="b")
    assert res.status == nf.STATUS_SKIPPED
    assert res.error_category == "no_recipients"


@pytest.mark.parametrize("exc,category", [
    (smtplib.SMTPAuthenticationError(535, b"bad creds"), "auth_failed"),
    (smtplib.SMTPRecipientsRefused({}), "recipient_refused"),
    (smtplib.SMTPSenderRefused(550, b"no", "s@x.com"), "sender_refused"),
    (smtplib.SMTPConnectError(421, b"nope"), "connect_failed"),
    (smtplib.SMTPServerDisconnected("gone"), "disconnected"),
    (ssl.SSLError("handshake"), "tls_failed"),
    (TimeoutError("slow"), "timeout"),
    (OSError("unreachable"), "network_error"),
    (smtplib.SMTPException("other"), "smtp_error"),
    (RuntimeError("surprise"), "unknown_error"),
])
def test_every_transport_failure_maps_to_a_category(exc, category):
    res = smtp(FakeTransport(raises=exc)).send_email(
        to=["a@x.com"], subject="s", body="b")
    assert res.status == nf.STATUS_FAILED
    assert res.error_category == category
    assert not res.ok


def test_smtp_failure_message_does_not_echo_the_transport_error():
    """A server banner can name internal hosts, and an auth error can echo the
    username. Only the category is reported."""
    res = smtp(FakeTransport(raises=smtplib.SMTPAuthenticationError(
        535, b"5.7.8 Username and Password not accepted for u@example.com"))
    ).send_email(to=["a@x.com"], subject="s", body="b")
    assert "Username and Password" not in (res.error or "")
    assert "u@example.com" not in (res.error or "")
    assert res.error_category == "auth_failed"


# ===========================================================================
# 3. credentials never escape
# ===========================================================================

def test_password_is_not_in_the_provider_repr():
    """A default repr would print the password into any traceback that captures
    locals -- which is how a credential reaches a log aggregator."""
    p = smtp()
    assert SECRET_PW not in repr(p)
    assert SECRET_PW not in str(p)
    assert "password=set" in repr(p)


def test_password_is_not_in_any_send_result():
    for t in (FakeTransport(), FakeTransport(raises=OSError("x"))):
        res = smtp(t).send_email(to=["a@x.com"], subject="s", body="b")
        assert SECRET_PW not in repr(res)


def test_password_is_not_in_the_resolved_provider_status():
    """This status dict is published on /health."""
    _, st = nf.resolve_email_provider({
        "requested": "smtp", "host": "h", "port": 587,
        "username": "u@example.com", "password": SECRET_PW,
        "sender": "a@x.com", "use_tls": True, "recipients_raw": "x@y.com",
    })
    blob = repr(st)
    assert SECRET_PW not in blob
    assert "u@example.com" not in blob, "username must not be published either"
    assert "x@y.com" not in blob, "recipient addresses must not be published"
    assert st["recipient_count"] == 1


def test_password_is_not_printed_when_a_send_fails(capsys):
    smtp(FakeTransport(raises=smtplib.SMTPAuthenticationError(535, b"no"))
         ).send_email(to=["a@x.com"], subject="s", body="b")
    captured = capsys.readouterr()
    assert SECRET_PW not in captured.out
    assert SECRET_PW not in captured.err


# ===========================================================================
# 4. configuration and selection
# ===========================================================================

def test_default_provider_is_console():
    p, st = nf.resolve_email_provider({"recipients_raw": "a@x.com"})
    assert isinstance(p, nf.ConsoleEmailProvider)
    assert st["provider"] == "console"
    assert st["degraded"] is False
    assert st["alerts_enabled"] is True


def test_smtp_selected_only_when_asked_for_explicitly():
    """A stray SMTP host in a shell profile must not start mailing an unknown
    relay."""
    p, st = nf.resolve_email_provider({
        "requested": "console", "host": "smtp.example.com",
        "sender": "a@x.com", "recipients_raw": "b@x.com"})
    assert isinstance(p, nf.ConsoleEmailProvider)
    assert st["provider"] == "console"
    assert st["degraded"] is False


def test_smtp_selected_when_asked_for_and_configured():
    p, st = nf.resolve_email_provider({
        "requested": "SMTP", "host": "smtp.example.com", "sender": "a@x.com",
        "recipients_raw": "b@x.com"})
    assert isinstance(p, nf.SMTPEmailProvider)
    assert st["provider"] == "smtp"
    assert st["degraded"] is False
    assert "NOT been verified against a live mail server" in st["note"]


def test_smtp_without_configuration_falls_back_to_console_and_says_so():
    """Never crash, and never pretend an email was delivered."""
    p, st = nf.resolve_email_provider({
        "requested": "smtp", "recipients_raw": "b@x.com"})
    assert isinstance(p, nf.ConsoleEmailProvider)
    assert st["provider"] == "console"
    assert st["requested_provider"] == "smtp"
    assert st["degraded"] is True
    assert "FRAUDSHIELD_SMTP_HOST" in st["note"]
    assert "NOT emailed" in st["note"]


def test_unknown_provider_falls_back_to_console():
    p, st = nf.resolve_email_provider({
        "requested": "sendgrid", "recipients_raw": "b@x.com"})
    assert isinstance(p, nf.ConsoleEmailProvider)
    assert st["degraded"] is True
    assert "sendgrid" in st["note"]


def test_no_recipients_reports_alerts_disabled_rather_than_implying_delivery():
    p, st = nf.resolve_email_provider({"requested": "console",
                                       "recipients_raw": ""})
    assert st["alerts_enabled"] is False
    assert "delivered to nobody" in st["note"]


@pytest.mark.parametrize("raw,expected", [
    ("a@x.com", ("a@x.com",)),
    ("a@x.com,b@x.com", ("a@x.com", "b@x.com")),
    ("a@x.com; b@x.com", ("a@x.com", "b@x.com")),
    ("  a@x.com ,, b@x.com  ", ("a@x.com", "b@x.com")),
    ("a@x.com,a@x.com", ("a@x.com",)),
    ("", ()),
    (None, ()),
    ("not-an-email", ()),
    ("@x.com", ()),
    ("a@", ()),
    ("a@x.com,broken,b@x.com", ("a@x.com", "b@x.com")),
])
def test_recipient_parsing_is_safe(raw, expected):
    assert nf.parse_recipients(raw) == expected


def test_a_malformed_recipient_is_dropped_and_counted_not_fatal():
    """One typo must not silence alerts for everyone else -- but it must be
    visible, or the mistake is permanent."""
    _, st = nf.resolve_email_provider({
        "requested": "console", "recipients_raw": "good@x.com, oops, b@x.com"})
    assert st["recipient_count"] == 2
    assert st["recipients_rejected"] == 1


def test_env_reader_uses_the_documented_names(monkeypatch):
    monkeypatch.setenv("FRAUDSHIELD_EMAIL_PROVIDER", "smtp")
    monkeypatch.setenv("FRAUDSHIELD_ALERT_FROM", "alerts@x.com")
    monkeypatch.setenv("FRAUDSHIELD_ALERT_RECIPIENTS", "a@x.com,b@x.com")
    monkeypatch.setenv("FRAUDSHIELD_SMTP_HOST", "smtp.x.com")
    monkeypatch.setenv("FRAUDSHIELD_SMTP_PORT", "2525")
    monkeypatch.setenv("FRAUDSHIELD_SMTP_USERNAME", "u")
    monkeypatch.setenv("FRAUDSHIELD_SMTP_PASSWORD", SECRET_PW)
    monkeypatch.setenv("FRAUDSHIELD_SMTP_USE_TLS", "false")
    cfg = nf.email_config_from_env()
    assert cfg["requested"] == "smtp"
    assert cfg["sender"] == "alerts@x.com"
    assert cfg["host"] == "smtp.x.com"
    assert cfg["port"] == 2525
    assert cfg["use_tls"] is False
    assert cfg["password"] == SECRET_PW


def test_malformed_port_falls_back_to_the_default(monkeypatch):
    monkeypatch.setenv("FRAUDSHIELD_SMTP_PORT", "not-a-number")
    assert nf.email_config_from_env()["port"] == 587


# ===========================================================================
# 5. message content
# ===========================================================================

RECORD = {
    "transaction_id": "pay_abc123", "order_id": "ord_abc123",
    "amount": 42999.0, "payment_method": "card", "settlement": "failed",
    "risk_score": 91.4, "decision": "BLOCK",
    "sub_scores": {"ml": 63.98, "rules": 18.28, "network": 0.0},
    "reason_codes": [{"code": "VELOCITY_10M", "severity": "high",
                      "detail": "7 attempts in 10 minutes"}],
    "fired_rules": ["velocity_burst"], "model_version": "m-1",
    "degraded": False, "override": None,
    "created_at": "2026-08-27T10:00:00+00:00",
}


def test_block_alert_contains_everything_an_analyst_needs():
    subject, body = nf.build_transaction_alert(
        event_type="BLOCK", record=RECORD, console_url="http://x/")
    assert subject == "[FraudShield] High-risk transaction blocked - pay_abc123"
    for needle in ("pay_abc123", "ord_abc123", "42,999", "card", "91.4",
                   "BLOCK", "7 attempts in 10 minutes", "velocity_burst",
                   "m-1", "2026-08-27T10:00:00+00:00", "http://x/admin"):
        assert needle in body, needle


def test_review_alert_says_the_payment_was_not_refused():
    record = {**RECORD, "decision": "MANUAL_REVIEW", "risk_score": 41.5,
              "settlement": "success"}
    subject, body = nf.build_transaction_alert(
        event_type="MANUAL_REVIEW", record=record)
    assert subject == "[FraudShield] Transaction requires review - pay_abc123"
    assert "MANUAL REVIEW" in body
    assert "was not refused" in body
    assert "human decision is required" in body


@pytest.mark.parametrize("event", ["BLOCK", "MANUAL_REVIEW"])
def test_no_alert_ever_claims_confirmed_fraud(event):
    _, body = nf.build_transaction_alert(event_type=event, record=RECORD)
    assert "NOT a confirmed fraud finding" in body
    assert "NOT an accusation against the customer" in body
    assert "Ground truth is created only when" in body
    # It never asserts the customer is a fraudster.
    assert "is fraudulent" not in body.lower()


@pytest.mark.parametrize("event", ["BLOCK", "MANUAL_REVIEW"])
def test_every_alert_states_that_customers_are_not_contacted(event):
    _, body = nf.build_transaction_alert(event_type=event, record=RECORD)
    assert "does not contact customers" in body


def test_block_alert_states_no_money_moved():
    _, body = nf.build_transaction_alert(event_type="BLOCK", record=RECORD)
    assert "BEFORE the payment provider was contacted" in body
    assert "no money moved" in body


def test_alert_carries_no_payment_credentials():
    """Email is the least controlled channel in the system."""
    record = {**RECORD, "instrument_display": "Visa \u2022\u2022\u2022\u2022 1111",
              "instrument_ref": "card_abc"}
    _, body = nf.build_transaction_alert(event_type="BLOCK", record=record)
    assert "4111" not in body
    assert "cvv" not in body.lower()
    assert "card_abc" not in body


def test_degraded_mode_is_stated_in_the_alert():
    _, body = nf.build_transaction_alert(
        event_type="BLOCK", record={**RECORD, "degraded": True})
    assert "ML layer unavailable" in body


def test_missing_reasons_render_as_absence_not_a_blank_gap():
    _, body = nf.build_transaction_alert(
        event_type="BLOCK",
        record={**RECORD, "reason_codes": [], "fired_rules": []})
    assert "(none recorded)" in body


def test_absent_console_url_says_so_rather_than_producing_a_broken_link():
    _, body = nf.build_transaction_alert(event_type="BLOCK", record=RECORD,
                                         console_url="")
    assert "FRAUDSHIELD_CONSOLE_URL" in body


def test_suspicious_ip_alert_uses_the_fingerprint_not_a_raw_address():
    flag = {"ip_hash": "ip_9f2a1c", "failures_total": 4, "accounts": 2,
            "since": "2026-08-27T10:00:00+00:00", "reason": "4 declines"}
    subject, body = nf.build_suspicious_ip_alert(
        flag=flag, window_minutes=60, threshold=3)
    assert "ip_9f2a1c" in subject and "ip_9f2a1c" in body
    assert "raw IP address is never stored" in body
    assert "3 declines within 60 minutes" in body
    assert "labels no transaction and no customer" in body
    # No dotted quad anywhere.
    assert not re.search(r"\b\d{1,3}(\.\d{1,3}){3}\b", body)


def test_promo_hold_alert_omits_the_payout_destination():
    redemption = {"redemption_id": "rdm_1", "promo_code": "WELCOME500",
                  "value": 500, "decision": "HOLD",
                  "reasons": [{"code": "DEVICE_REUSE", "detail": "3 accounts"}],
                  "fired_rules": ["device_reuse"], "device_fp": "dev_1",
                  "ip_hash": "ip_1", "payout_ref": "upi_secret_destination",
                  "created_at": "2026-08-27T10:00:00+00:00"}
    subject, body = nf.build_promo_hold_alert(redemption=redemption)
    assert "rdm_1" in subject
    assert "WELCOME500" in body and "500" in body
    assert "3 accounts" in body and "device_reuse" in body
    assert "upi_secret_destination" not in body
    assert "deliberately not included in email" in body


# ===========================================================================
# 6. routing: only events that need a human
# ===========================================================================

def test_allow_generates_no_notification(db, pinned_scorer):
    with app_run() as c:
        h = register(c, f"al-{uuid.uuid4().hex[:8]}@example.com")
        body = order(c, h, P_ALLOW)
        assert body["status"] == "confirmed"
        assert sent_messages() == []
        assert notif_records() == []
        assert backend.NOTIFICATION_SENT not in audit_actions()


def test_manual_review_generates_exactly_one_notification(db, pinned_scorer):
    with app_run() as c:
        h = register(c, f"mr-{uuid.uuid4().hex[:8]}@example.com")
        body = order(c, h, P_REVIEW)
        msgs = sent_messages()
        recs = notif_records()

        assert len(msgs) == 1
        assert "requires review" in msgs[0].subject
        assert len(recs) == 1
        assert recs[0]["event_type"] == "MANUAL_REVIEW"
        assert recs[0]["status"] == nf.STATUS_SENT
        assert recs[0]["order_id"] == body["order_id"]


def test_block_generates_exactly_one_notification(db, pinned_scorer):
    with app_run() as c:
        h = register(c, f"bl-{uuid.uuid4().hex[:8]}@example.com")
        order(c, h, P_BLOCK)
        msgs = sent_messages()
        recs = notif_records()

        assert len(msgs) == 1
        assert "blocked" in msgs[0].subject
        assert recs[0]["event_type"] == "BLOCK"


def test_alert_goes_to_every_configured_recipient(db, pinned_scorer):
    with app_run() as c:
        h = register(c, f"multi-{uuid.uuid4().hex[:8]}@example.com")
        order(c, h, P_BLOCK)
        msg = sent_messages()[0]
        rec = notif_records()[0]

        assert msg.to == ("analyst@fraudshield.local", "admin@fraudshield.local")
        assert rec["recipient_count"] == 2


def test_ordinary_successful_traffic_produces_no_alerts(db, pinned_scorer):
    """Six ALLOW orders, zero emails. An alert stream containing routine traffic
    is one nobody reads."""
    with app_run() as c:
        for i in range(6):
            h = register(c, f"quiet{i}-{uuid.uuid4().hex[:8]}@example.com")
            order(c, h, P_ALLOW)
        assert sent_messages() == []


def test_suspicious_ip_generates_a_notification(db, pinned_scorer):
    """A decline burst from one address flags it, and the flag alerts."""
    with app_run() as c:
        for i in range(backend.IP_FAIL_THRESHOLD + 1):
            h = register(c, f"ip{i}-{uuid.uuid4().hex[:8]}@example.com")
            order(c, h, P_BLOCK)      # BLOCK always settles failed
        events = [r["event_type"] for r in notif_records()]
        ip_alerts = [r for r in notif_records()
                     if r["event_type"] == nf.EVENT_SUSPICIOUS_IP]

        assert nf.EVENT_SUSPICIOUS_IP in events
        # One alert on the transition, not one per decline.
        assert len(ip_alerts) == 1
        assert ip_alerts[0]["ip_hash"]


def test_promo_hold_generates_a_notification(db, pinned_scorer):
    with app_run() as c:
        # Reuse one device and payout across accounts to force HOLD/DENY.
        for i in range(5):
            h = register(c, f"pr{i}-{uuid.uuid4().hex[:8]}@example.com")
            c.post("/v1/promo/redeem", headers=h, json={
                "promo_code": "WELCOME500", "device_fp": "dev_shared_notify",
                "payout_ref": "upi_shared_notify"})
        promo = [r for r in notif_records()
                 if r["event_type"] == nf.EVENT_PROMO_HOLD]

        assert promo, "a promo hold produced no analyst alert"
        assert promo[0]["promo_code"] == "WELCOME500"
        assert promo[0]["decision"] in backend.PROMO_QUEUED_DECISIONS


def test_webhook_manual_review_alerts(db, pinned_scorer):
    with app_run() as c:
        raw, sig, _ = signed_event(status="captured", amount_paise=2749900)
        r = c.post("/v1/webhooks/payment", content=raw,
                   headers={"x-razorpay-signature": sig,
                            "content-type": "application/json"})
        assert r.json()["ingested"] is True
        recs = notif_records()

        assert len(recs) == 1
        assert recs[0]["event_type"] == "MANUAL_REVIEW"


def test_dry_run_scoring_alerts_nobody(db, pinned_scorer):
    """A preview routes nothing, so it must not email the team."""
    with app_run() as c:
        c.post("/v1/risk/score", json={
            "customer_id": "cust_dry", "amount": P_BLOCK[1],
            "payment_method": "card", "device_fp": "dev_dry",
            "ip_hash": "ip_dry", "commit": False})
        assert notif_records() == []


def test_committed_service_scoring_alerts(db, pinned_scorer):
    with app_run() as c:
        c.post("/v1/risk/score", json={
            "customer_id": "cust_svc", "amount": P_BLOCK[1],
            "payment_method": "card", "device_fp": "dev_svc",
            "ip_hash": "ip_svc", "commit": True})
        recs = notif_records()

        assert len(recs) == 1
        assert recs[0]["event_type"] == "BLOCK"


# ===========================================================================
# 7. reliability: email must never break the payment path
# ===========================================================================

def test_a_provider_that_raises_does_not_fail_the_order(db, pinned_scorer):
    """The single most important test in this file."""
    with app_run() as c:
        backend.STATE["email_provider"] = ExplodingProvider()
        h = register(c, f"boom-{uuid.uuid4().hex[:8]}@example.com")
        r = c.post("/v1/orders", headers=h, json={
            "items": [{"product_id": P_BLOCK[0], "qty": 1}],
            "payment_method": "card", "device_fp": "dev_boom", "card": CARD})

        assert r.status_code == 201, "an email failure broke checkout"
        body = r.json()
        assert body["status"] == "declined"
        assert body["settlement"] == "failed"


def test_block_still_blocks_when_email_fails(db, pinned_scorer):
    with app_run() as c:
        backend.STATE["email_provider"] = FailingProvider()
        h = register(c, f"blk-{uuid.uuid4().hex[:8]}@example.com")
        body = order(c, h, P_BLOCK)
        txn_id = next(t for t, v in backend.STATE["txns"].items()
                      if v.get("order_id") == body["order_id"])
        stored = backend.STATE["txns"][txn_id]

        assert stored["decision"] == "BLOCK"
        assert body["settlement"] == "failed"
        assert backend.RISK_DECISION in audit_actions()


def test_manual_review_still_reaches_the_queue_when_email_fails(db,
                                                               pinned_scorer):
    with app_run() as c:
        backend.STATE["email_provider"] = FailingProvider()
        h = register(c, f"mrq-{uuid.uuid4().hex[:8]}@example.com")
        body = order(c, h, P_REVIEW)
        txn_id = next(t for t, v in backend.STATE["txns"].items()
                      if v.get("order_id") == body["order_id"])

        assert txn_id in backend.STATE["queue"]
        assert c.get("/v1/admin/queue",
                     headers=staff(c, "mrq_s")).json()["count"] >= 1


def test_audit_and_persistence_survive_an_email_failure(db, pinned_scorer):
    with app_run() as c:
        backend.STATE["email_provider"] = FailingProvider()
        h = register(c, f"aud-{uuid.uuid4().hex[:8]}@example.com")
        body = order(c, h, P_BLOCK)
        txn_id = next(t for t, v in backend.STATE["txns"].items()
                      if v.get("order_id") == body["order_id"])

    # The durable transaction record is intact.
    assert db.get(f"TXN#{txn_id}", "DETAIL") is not None
    # And the risk decision was audited.
    day = backend.datetime.now(backend.timezone.utc).isoformat()[:10]
    rows = db.query_prefix(f"AUDIT#{day}", "")
    assert any(r["action"] == backend.RISK_DECISION for r in rows)


def test_a_failed_notification_is_recorded(db, pinned_scorer):
    with app_run() as c:
        backend.STATE["email_provider"] = FailingProvider()
        h = register(c, f"failrec-{uuid.uuid4().hex[:8]}@example.com")
        order(c, h, P_BLOCK)
        recs = notif_records()

        assert len(recs) == 1
        assert recs[0]["status"] == nf.STATUS_FAILED
        assert recs[0]["error_category"] == "auth_failed"
        assert recs[0]["sent_at"] is None
        assert recs[0]["attempts"] == 1


def test_a_failed_notification_is_visible_but_not_customer_facing(db,
                                                                 pinned_scorer):
    with app_run() as c:
        backend.STATE["email_provider"] = FailingProvider()
        h = register(c, f"vis-{uuid.uuid4().hex[:8]}@example.com")
        body = order(c, h, P_BLOCK)

        # Never in the customer's response.
        blob = repr(body)
        assert "auth_failed" not in blob
        assert "SMTP" not in blob
        assert "notification" not in blob.lower()

        # But visible to staff.
        got = c.get("/v1/admin/notifications?status=failed",
                    headers=staff(c, "vis_s")).json()
        assert got["count"] == 1
        assert got["items"][0]["error_category"] == "auth_failed"


def test_a_webhook_still_ingests_when_email_fails(db, pinned_scorer):
    with app_run() as c:
        backend.STATE["email_provider"] = ExplodingProvider()
        raw, sig, _ = signed_event(status="captured", amount_paise=4299900)
        r = c.post("/v1/webhooks/payment", content=raw,
                   headers={"x-razorpay-signature": sig,
                            "content-type": "application/json"})
        assert r.status_code == 200
        assert r.json()["ingested"] is True
        assert r.json()["decision"] == "BLOCK"


def test_a_promo_hold_is_still_recorded_when_email_fails(db, pinned_scorer):
    with app_run() as c:
        backend.STATE["email_provider"] = ExplodingProvider()
        for i in range(5):
            h = register(c, f"pf{i}-{uuid.uuid4().hex[:8]}@example.com")
            r = c.post("/v1/promo/redeem", headers=h, json={
                "promo_code": "WELCOME500", "device_fp": "dev_promo_fail",
                "payout_ref": "upi_promo_fail"})
            assert r.status_code == 201
        assert backend.STATE["promo_queue"], "holds were lost"


def test_an_unavailable_record_store_does_not_break_notification(db,
                                                                pinned_scorer,
                                                                monkeypatch):
    """Bookkeeping is best effort too. A store outage must not escalate."""
    original = backend.InMemoryRecordStore.put

    def flaky(self, pk, sk, item):
        if pk.startswith("NOTIFICATION#"):
            raise RuntimeError("store down")
        return original(self, pk, sk, item)

    with app_run() as c:
        monkeypatch.setattr(backend.InMemoryRecordStore, "put", flaky)
        h = register(c, f"nostore-{uuid.uuid4().hex[:8]}@example.com")
        r = c.post("/v1/orders", headers=h, json={
            "items": [{"product_id": P_BLOCK[0], "qty": 1}],
            "payment_method": "card", "device_fp": "dev_nostore", "card": CARD})
        assert r.status_code == 201
        recs = notif_records()

        # Still recorded in memory, and honestly flagged as not durable.
        assert len(recs) == 1
        assert recs[0]["durable"] is False


# ===========================================================================
# 8. deduplication
# ===========================================================================

def test_dedupe_key_is_deterministic_and_case_insensitive():
    assert nf.dedupe_key("MANUAL_REVIEW", "pay_1") == "manual_review:pay_1"
    assert nf.dedupe_key("manual_review", "pay_1") == \
        nf.dedupe_key("MANUAL_REVIEW", "pay_1")
    assert nf.dedupe_key(nf.EVENT_SUSPICIOUS_IP, "ip_x") == "suspicious_ip:ip_x"
    assert nf.dedupe_key(nf.EVENT_PROMO_HOLD, "rdm_x") == "promo_hold:rdm_x"


def test_the_same_transaction_notifies_once(db, pinned_scorer):
    with app_run() as c:
        h = register(c, f"dup-{uuid.uuid4().hex[:8]}@example.com")
        body = order(c, h, P_BLOCK)
        rec = next(v for v in backend.STATE["txns"].values()
                   if v.get("order_id") == body["order_id"])

        assert len(sent_messages()) == 1
        for _ in range(5):
            again = backend.notify_transaction(rec)
            assert again["status"] == nf.STATUS_SUPPRESSED
        assert len(sent_messages()) == 1, "duplicate alerts were sent"


def test_a_decline_burst_from_one_address_sends_one_ip_alert(db, pinned_scorer):
    """The anti-spam property. Twelve declines, one address alert."""
    with app_run() as c:
        for i in range(12):
            h = register(c, f"burst{i}-{uuid.uuid4().hex[:8]}@example.com")
            order(c, h, P_BLOCK)
        ip_alerts = [m for m in sent_messages()
                     if "Address flagged" in m.subject]

        assert len(ip_alerts) == 1, \
            f"burst produced {len(ip_alerts)} address alerts"


def test_a_redelivered_webhook_creates_no_duplicate_notification(db,
                                                                pinned_scorer):
    with app_run() as c:
        raw, sig, _ = signed_event(status="captured", amount_paise=4299900)
        headers = {"x-razorpay-signature": sig,
                   "content-type": "application/json"}
        first = c.post("/v1/webhooks/payment", content=raw, headers=headers)
        again = c.post("/v1/webhooks/payment", content=raw, headers=headers)

        assert first.json()["ingested"] is True
        assert again.json()["duplicate"] is True
        assert len(sent_messages()) == 1


def test_dedupe_survives_a_restart(db, pinned_scorer):
    """A deploy between a webhook and its redelivery must not re-alert."""
    with app_run() as c:
        h = register(c, f"rest-{uuid.uuid4().hex[:8]}@example.com")
        body = order(c, h, P_BLOCK)
        rec = next(v for v in backend.STATE["txns"].values()
                   if v.get("order_id") == body["order_id"])
        assert len(sent_messages()) == 1

    assert backend.STATE == {}

    with app_run():
        # Same event, fresh process, shared store.
        out = backend.notify_transaction(rec)
        assert out["status"] == nf.STATUS_SUPPRESSED
        assert sent_messages() == [], "a restart re-sent an existing alert"


def test_distinct_transactions_each_notify(db, pinned_scorer):
    """Dedupe must not suppress genuinely different events."""
    with app_run() as c:
        for i in range(3):
            h = register(c, f"dist{i}-{uuid.uuid4().hex[:8]}@example.com")
            order(c, h, P_REVIEW)
        review_alerts = [m for m in sent_messages()
                         if "requires review" in m.subject]
        assert len(review_alerts) == 3


def test_a_promo_hold_notifies_once_per_redemption(db, pinned_scorer):
    with app_run() as c:
        for i in range(5):
            h = register(c, f"pd{i}-{uuid.uuid4().hex[:8]}@example.com")
            c.post("/v1/promo/redeem", headers=h, json={
                "promo_code": "WELCOME500", "device_fp": "dev_promo_dup",
                "payout_ref": "upi_promo_dup"})

        promo_alerts = [r for r in notif_records()
                        if r["event_type"] == nf.EVENT_PROMO_HOLD]
        # One per held redemption, and no more.
        assert promo_alerts
        assert len(promo_alerts) == len({r["redemption_id"]
                                        for r in promo_alerts})

        # Re-notifying an existing hold is suppressed.
        idx = db.get("INDEX#PROMO", promo_alerts[0]["redemption_id"])
        stored = db.get(f"CUSTOMER#{idx['customer_id']}", idx["sk"])
        assert backend.notify_promo_hold(stored)["status"] == \
            nf.STATUS_SUPPRESSED


# ===========================================================================
# 9. audit
# ===========================================================================

def test_a_successful_notification_emits_notification_sent(db, pinned_scorer):
    with app_run() as c:
        h = register(c, f"as-{uuid.uuid4().hex[:8]}@example.com")
        order(c, h, P_BLOCK)
        events = [e for e in backend.STATE["audit"]
                  if e["action"] == backend.NOTIFICATION_SENT]

        assert len(events) == 1
        ev = events[0]
        assert ev["actor"] == "system:notifier"
        assert ev["event_id"].startswith("ntf_")
        assert ev["before"]["event_type"] == "BLOCK"
        assert ev["before"]["transaction_id"]
        assert ev["after"]["status"] == nf.STATUS_SENT
        assert ev["after"]["recipient_count"] == 2
        assert ev["after"]["provider"] == "console"
        assert ev["at"].endswith("+00:00")


def test_a_failed_notification_emits_notification_failed(db, pinned_scorer):
    with app_run() as c:
        backend.STATE["email_provider"] = FailingProvider()
        h = register(c, f"af-{uuid.uuid4().hex[:8]}@example.com")
        order(c, h, P_BLOCK)
        events = [e for e in backend.STATE["audit"]
                  if e["action"] == backend.NOTIFICATION_FAILED]

        assert len(events) == 1
        assert events[0]["after"]["status"] == nf.STATUS_FAILED
        assert events[0]["after"]["error_category"] == "auth_failed"
        assert backend.NOTIFICATION_SENT not in audit_actions()


def test_a_notification_is_never_ground_truth(db, pinned_scorer):
    """Delivering an email proves an email was delivered. Nothing else."""
    with app_run() as c:
        h = register(c, f"gt-{uuid.uuid4().hex[:8]}@example.com")
        order(c, h, P_BLOCK)
        ev = [e for e in backend.STATE["audit"]
              if e["action"] == backend.NOTIFICATION_SENT][0]

        assert ev["after"]["is_ground_truth"] is False
        assert "NOT ground truth" in ev["after"]["note"]
        assert "NOT a risk decision" in ev["after"]["note"]
        # And no label was created.
        assert backend.OUTCOME_RECORDED not in audit_actions()


def test_notification_events_are_distinct_from_risk_and_outcome(db,
                                                               pinned_scorer):
    with app_run() as c:
        h = register(c, f"sep-{uuid.uuid4().hex[:8]}@example.com")
        body = order(c, h, P_REVIEW)
        txn_id = next(t for t, v in backend.STATE["txns"].items()
                      if v.get("order_id") == body["order_id"])
        st = staff(c, "sep_s")
        c.post(f"/v1/admin/transactions/{txn_id}/outcome", headers=st,
               json={"label": "fraud"})
        by_action: dict = {}
        for e in backend.STATE["audit"]:
            by_action.setdefault(e["action"], []).append(e)

        # Three separate events, three separate actors, three separate meanings.
        assert by_action[backend.RISK_DECISION][0]["actor"] == "system:scorer"
        assert by_action[backend.NOTIFICATION_SENT][0]["actor"] == \
            "system:notifier"
        assert "@" in by_action[backend.OUTCOME_RECORDED][0]["actor"]
        assert by_action[backend.RISK_DECISION][0]["after"][
            "is_ground_truth"] is False
        assert by_action[backend.NOTIFICATION_SENT][0]["after"][
            "is_ground_truth"] is False
        assert by_action[backend.OUTCOME_RECORDED][0]["after"][
            "ground_truth"] is True


def test_audit_record_carries_no_credentials_or_addresses(db, pinned_scorer):
    with app_run() as c:
        # A transport-injected SMTP provider, so nothing hits the network.
        backend.STATE["email_provider"] = nf.SMTPEmailProvider(
            host="smtp.x.com", sender="alerts@x.com",
            username="smtp-user@x.com", password=SECRET_PW,
            transport=FakeTransport())
        h = register(c, f"nocred-{uuid.uuid4().hex[:8]}@example.com")
        order(c, h, P_BLOCK)
        ev = [e for e in backend.STATE["audit"]
              if e["action"] == backend.NOTIFICATION_SENT][0]

        blob = repr(ev)
        assert SECRET_PW not in blob
        assert "smtp-user@x.com" not in blob
        assert "analyst@fraudshield.local" not in blob, \
            "recipient addresses must not be in the audit record"
        assert ev["after"]["recipient_count"] == 2


def test_a_suppressed_duplicate_emits_no_audit_event(db, pinned_scorer):
    with app_run() as c:
        h = register(c, f"sup-{uuid.uuid4().hex[:8]}@example.com")
        body = order(c, h, P_BLOCK)
        rec = next(v for v in backend.STATE["txns"].values()
                   if v.get("order_id") == body["order_id"])
        before = len([e for e in backend.STATE["audit"]
                      if e["action"] == backend.NOTIFICATION_SENT])
        backend.notify_transaction(rec)
        after = len([e for e in backend.STATE["audit"]
                     if e["action"] == backend.NOTIFICATION_SENT])
        assert before == after == 1


# ===========================================================================
# 10. admin visibility
# ===========================================================================

def test_notification_endpoint_lists_deliveries(db, pinned_scorer):
    with app_run() as c:
        h = register(c, f"list-{uuid.uuid4().hex[:8]}@example.com")
        order(c, h, P_BLOCK)
        got = c.get("/v1/admin/notifications",
                    headers=staff(c, "list_s", role="analyst")).json()

        assert got["count"] == 1
        item = got["items"][0]
        assert item["event_type"] == "BLOCK"
        assert item["status"] == "sent"
        assert item["provider"] == "console"
        assert item["recipient_count"] == 2
        assert item["transaction_id"]
        assert item["created_at"] and item["sent_at"]
        assert got["counts"] == {"total": 1, "sent": 1, "failed": 0,
                                 "skipped": 0}


def test_notification_endpoint_never_exposes_recipients_or_bodies(db,
                                                                 pinned_scorer):
    """An explicit allow-list, like the customer order projection."""
    with app_run() as c:
        h = register(c, f"proj-{uuid.uuid4().hex[:8]}@example.com")
        order(c, h, P_BLOCK)
        got = c.get("/v1/admin/notifications",
                    headers=staff(c, "proj_s")).json()

        item = got["items"][0]
        assert "analyst@fraudshield.local" not in repr(item)
        assert "recipients" not in item
        assert "body" not in item
        assert "subject" not in item
        # The raw transport error is withheld; only the category is published.
        assert "error" not in item
        assert "error_category" in item


@pytest.mark.parametrize("query,expected", [
    ("?status=failed", 1),
    ("?status=sent", 0),
    ("?event_type=BLOCK", 1),
    ("?event_type=MANUAL_REVIEW", 0),
    ("?event_type=block", 1),
])
def test_notification_endpoint_filters(db, pinned_scorer, query, expected):
    with app_run() as c:
        backend.STATE["email_provider"] = FailingProvider()
        h = register(c, f"filt-{uuid.uuid4().hex[:8]}@example.com")
        order(c, h, P_BLOCK)
        got = c.get(f"/v1/admin/notifications{query}",
                    headers=staff(c, "filt_s")).json()
        assert got["count"] == expected
        # Pre-filter counts are always reported, so a filtered view still shows
        # that failures exist.
        assert got["counts"]["failed"] == 1


def test_notification_endpoint_requires_staff(db, pinned_scorer):
    with app_run() as c:
        h = register(c, f"acl-{uuid.uuid4().hex[:8]}@example.com")
        assert c.get("/v1/admin/notifications",
                     headers=h).status_code == 403
        assert c.get("/v1/admin/notifications").status_code in (401, 403)


def test_notification_endpoint_publishes_mode_without_credentials(db,
                                                                 pinned_scorer):
    with app_run() as c:
        got = c.get("/v1/admin/notifications",
                    headers=staff(c, "mode_s")).json()
        assert got["email"]["provider"] == "console"
        assert got["email"]["alerts_enabled"] is True
        assert "password" not in repr(got["email"]).lower()
        assert "analyst@fraudshield.local" not in repr(got["email"])
        assert "not a risk decision" in got["note"].lower()


# ===========================================================================
# 11. health
# ===========================================================================

def test_health_reports_email_mode_safely(db, pinned_scorer):
    with app_run() as c:
        h = c.get("/health").json()
        e = h["email_notifications"]

        assert e["provider"] == "console"
        assert e["configured"] is True
        assert e["degraded"] is False
        assert e["alerts_enabled"] is True
        assert e["recipient_count"] == 2
        assert e["sent"] == 0 and e["failed"] == 0


def test_health_counts_sent_and_failed(db, pinned_scorer):
    with app_run() as c:
        h1 = register(c, f"hc1-{uuid.uuid4().hex[:8]}@example.com")
        order(c, h1, P_BLOCK)
        backend.STATE["email_provider"] = FailingProvider()
        h2 = register(c, f"hc2-{uuid.uuid4().hex[:8]}@example.com")
        order(c, h2, P_REVIEW)
        e = c.get("/health").json()["email_notifications"]

        assert e["sent"] == 1
        assert e["failed"] == 1


def test_health_never_exposes_credentials_or_recipients(db, monkeypatch):
    monkeypatch.setattr(backend, "_EMAIL_CFG", {
        "requested": "smtp", "sender": "alerts@secret.example",
        "recipients_raw": "secret-analyst@secret.example",
        "host": "smtp.secret.example", "port": 587,
        "username": "secret-user@secret.example", "password": SECRET_PW,
        "use_tls": True, "console_url": "",
    })
    with app_run() as c:
        blob = repr(c.get("/health").json())

    assert SECRET_PW not in blob
    assert "secret-user@secret.example" not in blob
    assert "secret-analyst@secret.example" not in blob
    # The sender and host are not published either.
    assert "smtp.secret.example" not in blob
    assert "alerts@secret.example" not in blob


def test_health_reports_degradation_when_smtp_is_unconfigured(db, monkeypatch):
    monkeypatch.setattr(backend, "_EMAIL_CFG", {
        "requested": "smtp", "sender": "", "recipients_raw": RECIPIENTS,
        "host": "", "port": 587, "username": "", "password": "",
        "use_tls": True, "console_url": "",
    })
    with app_run() as c:
        e = c.get("/health").json()["email_notifications"]

    assert e["provider"] == "console"
    assert e["degraded"] is True
    assert "NOT emailed" in e["note"]


def test_degraded_email_warns_at_startup(db, monkeypatch, capsys):
    monkeypatch.setattr(backend, "_EMAIL_CFG", {
        "requested": "smtp", "sender": "", "recipients_raw": RECIPIENTS,
        "host": "", "port": 587, "username": "", "password": "",
        "use_tls": True, "console_url": "",
    })
    with app_run():
        pass
    assert "EMAIL ALERTS DEGRADED" in capsys.readouterr().out


# ===========================================================================
# 12. the customer never learns any of this
# ===========================================================================

def test_a_customer_response_never_mentions_a_notification(db, pinned_scorer):
    with app_run() as c:
        h = register(c, f"cust-{uuid.uuid4().hex[:8]}@example.com")
        for product in (P_ALLOW, P_REVIEW, P_BLOCK):
            body = order(c, h, product)
            blob = repr(body).lower()
            for forbidden in ("notification", "email", "alert", "analyst",
                              "smtp", "recipient"):
                assert forbidden not in blob, f"{forbidden} leaked to a customer"


def test_a_customer_order_view_never_mentions_a_notification(db, pinned_scorer):
    with app_run() as c:
        h = register(c, f"cv-{uuid.uuid4().hex[:8]}@example.com")
        body = order(c, h, P_BLOCK)
        one = c.get(f"/v1/orders/{body['order_id']}", headers=h).json()
        listed = c.get("/v1/orders", headers=h).json()

        for blob in (repr(one).lower(), repr(listed).lower()):
            assert "notification" not in blob
            assert "smtp" not in blob


def test_no_customer_email_address_is_ever_a_recipient(db, pinned_scorer):
    """The hard limit: FraudShield never emails the payer."""
    with app_run() as c:
        email = f"payer-{uuid.uuid4().hex[:8]}@example.com"
        h = register(c, email)
        order(c, h, P_BLOCK)

        for msg in sent_messages():
            assert email not in msg.to
            assert all(r.endswith("@fraudshield.local") for r in msg.to)


def test_the_alertable_event_list_excludes_routine_traffic():
    """A guard on the constant itself: adding ALLOW here would be a product
    change, not a configuration one."""
    assert "ALLOW" not in nf.ALERTABLE_EVENTS
    assert set(nf.ALERTABLE_EVENTS) == {
        "MANUAL_REVIEW", "BLOCK", "SUSPICIOUS_IP", "PROMO_HOLD"}
