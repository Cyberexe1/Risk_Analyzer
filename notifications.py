"""Analyst email notification.

WHY THIS MODULE EXISTS
----------------------
A review queue nobody is watching is a queue that grows. FraudShield already
routes risk to a human; this tells that human it happened, so the gap between
"transaction flagged" and "analyst looks at it" is not measured in hours.

    scoring -> ALLOW / MANUAL_REVIEW / BLOCK
                        |
              needs human attention?
                        |
              EmailProvider.send()      <-- this module
                        |
              analyst opens the console, reviews evidence,
              records a human outcome

WHAT THIS MODULE IS NOT ALLOWED TO DO
-------------------------------------
Three hard limits, all of them load-bearing:

  1. **It never emails a customer.** Not a warning, not a notice, not an
     "unusual activity" note. Telling a payer they were flagged tells a card
     tester exactly what to rotate, and telling an innocent customer they are
     under suspicion is a harm the product has no right to inflict.

  2. **It never becomes a dependency of the risk decision.** Email is best
     effort and always downstream. A BLOCK blocks whether or not SMTP is
     reachable; see the failure contract on `notify()` in backend.py.

  3. **It never claims fraud.** An alert reports a routing decision and the
     evidence behind it. `BLOCK` means the score crossed a configured
     threshold -- it is not a finding, and every message says so in as many
     words.

WHAT THIS MODULE DOES NOT CONTAIN
---------------------------------
No scoring, no persistence, no audit, no dedupe. Providers speak to transports;
FraudShield decides risk. Dedupe and audit need the record store, so they live in
backend.py -- and the dependency stays one-way: backend imports notifications,
notifications never imports backend.

HONEST STATUS
-------------
`ConsoleEmailProvider` is the default and is fully exercised. `SMTPEmailProvider`
is written against the standard library's documented `smtplib` surface and tested
against an injected fake transport. Whether it delivers to a particular real mail
server depends on credentials this repository does not ship -- so the README says
"not verified against a live SMTP server" rather than claiming delivery works.
"""
from __future__ import annotations

import os
import smtplib
import ssl
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.message import EmailMessage
from typing import Protocol

# ---------------------------------------------------------------------------
# vocabulary
# ---------------------------------------------------------------------------

PROVIDER_CONSOLE = "console"
PROVIDER_SMTP = "smtp"

STATUS_SENT = "sent"
STATUS_FAILED = "failed"
STATUS_SUPPRESSED = "suppressed"      # deduplicated: a real event, not an error
STATUS_SKIPPED = "skipped"            # nothing to send to

# The only events that warrant waking a human. Deliberately short.
#
# Absent on purpose: ALLOW, ordinary successful payments, every webhook
# ingestion, every audit event, every score. An alert stream that includes
# routine traffic is an alert stream nobody reads, and the first thing an analyst
# does with it is build a filter -- at which point the real alerts are filtered
# out too.
EVENT_MANUAL_REVIEW = "MANUAL_REVIEW"
EVENT_BLOCK = "BLOCK"
EVENT_SUSPICIOUS_IP = "SUSPICIOUS_IP"
EVENT_PROMO_HOLD = "PROMO_HOLD"

ALERTABLE_EVENTS = (EVENT_MANUAL_REVIEW, EVENT_BLOCK,
                    EVENT_SUSPICIOUS_IP, EVENT_PROMO_HOLD)

# Restated in every message body. The single most important sentence here: an
# automated routing decision is not a human fraud finding, and an alert that
# blurred the two would train analysts to treat a score as a verdict.
NOT_A_VERDICT = (
    "This is an automated routing decision, NOT a confirmed fraud finding and "
    "NOT an accusation against the customer. Ground truth is created only when "
    "an authorised reviewer records an outcome in the FraudShield console."
)

NO_CUSTOMER_CONTACT = (
    "FraudShield does not contact customers about risk decisions. This alert is "
    "for authorised analysts and administrators only."
)


class EmailError(Exception):
    """An email could not be sent. Carries an operator-facing reason only."""


@dataclass
class EmailMessageSpec:
    """One message, fully rendered, before any transport touches it.

    Separated from sending so the body can be asserted in a test without a
    provider, and so the same spec can be handed to either provider unchanged.
    """

    to: tuple[str, ...]
    subject: str
    body: str
    event_type: str
    # Non-secret context for logs and the audit record. Never carries credentials.
    metadata: dict = field(default_factory=dict)


@dataclass
class SendResult:
    """Outcome of one delivery attempt."""

    provider: str
    status: str
    recipient_count: int
    error: str | None = None
    # Coarse bucket for the audit record, so a reader can distinguish "wrong
    # password" from "host unreachable" without the message text being stored.
    error_category: str | None = None

    @property
    def ok(self) -> bool:
        return self.status == STATUS_SENT


# ---------------------------------------------------------------------------
# interface
# ---------------------------------------------------------------------------

class EmailProvider(Protocol):
    """Only what this application actually does with email: send an alert.

    Deliberately absent: templates, attachments, HTML bodies, unsubscribe
    handling, bounce processing, threading. None of it is used, and each one
    would make the interface look more capable than the product is.
    """

    provider_name: str

    def is_configured(self) -> bool: ...

    def send_email(self, *, to: tuple[str, ...] | list[str], subject: str,
                   body: str, metadata: dict | None = None) -> SendResult: ...


# ---------------------------------------------------------------------------
# console provider -- the default
# ---------------------------------------------------------------------------

DEMO_RULE = "=" * 62


class ConsoleEmailProvider:
    """Renders the alert instead of transmitting it.

    This is the DEFAULT, and it is not a stub. It does the one honest thing a
    credential-free environment can do: show exactly what would have been sent,
    to whom, with the full body. A demo, a test and a local run all see the real
    message.

    It is also explicitly NOT a claim of delivery. `SendResult.status` is `sent`
    because the provider did its job -- rendering -- and the provider name in the
    audit record is `console`, so no reader can mistake a rendered alert for a
    delivered one.
    """

    provider_name = PROVIDER_CONSOLE

    def __init__(self, *, echo: bool = True, sink=None):
        # `echo` writes the banner to stdout, which is what makes the demo work.
        # `sink` lets a test capture without touching stdout.
        self.echo = echo
        self._sink = sink if sink is not None else []

    def is_configured(self) -> bool:
        """Always true. Rendering needs no credentials, which is the point."""
        return True

    @property
    def sent(self) -> list[EmailMessageSpec]:
        """Every message this provider has rendered, newest last.

        The inspection hook the tests use. A list rather than a callback because
        a test wants to assert on the Nth message, and a counter would lose the
        body.
        """
        return list(self._sink)

    def clear(self) -> None:
        self._sink.clear()

    def send_email(self, *, to, subject, body,
                   metadata: dict | None = None) -> SendResult:
        spec = EmailMessageSpec(
            to=tuple(to), subject=subject, body=body,
            event_type=str((metadata or {}).get("event_type") or ""),
            metadata=dict(metadata or {}),
        )
        self._sink.append(spec)
        if self.echo:
            print(self.render(spec))
        return SendResult(provider=self.provider_name, status=STATUS_SENT,
                          recipient_count=len(spec.to))

    @staticmethod
    def render(spec: EmailMessageSpec) -> str:
        """The demo banner. Deliberately loud and deliberately complete."""
        return (
            f"\n{DEMO_RULE}\n"
            f"FraudShield EMAIL ALERT   (console provider -- NOT transmitted)\n"
            f"{DEMO_RULE}\n"
            f"To: {', '.join(spec.to)}\n"
            f"Subject: {spec.subject}\n"
            f"{DEMO_RULE}\n"
            f"{spec.body}\n"
            f"{DEMO_RULE}\n"
        )


# ---------------------------------------------------------------------------
# SMTP provider
# ---------------------------------------------------------------------------

def _error_category(exc: BaseException) -> str:
    """Coarse bucket for an SMTP failure.

    Categories rather than messages, because the message can echo back the
    username, the envelope, or a server banner naming internal hosts -- and an
    audit record readable by every admin is the wrong place for any of it.
    """
    if isinstance(exc, smtplib.SMTPAuthenticationError):
        return "auth_failed"
    if isinstance(exc, smtplib.SMTPRecipientsRefused):
        return "recipient_refused"
    if isinstance(exc, smtplib.SMTPSenderRefused):
        return "sender_refused"
    if isinstance(exc, smtplib.SMTPConnectError):
        return "connect_failed"
    if isinstance(exc, smtplib.SMTPServerDisconnected):
        return "disconnected"
    if isinstance(exc, ssl.SSLError):
        return "tls_failed"
    if isinstance(exc, TimeoutError):
        return "timeout"
    # SMTPException BEFORE OSError, and this ordering is load-bearing:
    # smtplib.SMTPException subclasses OSError, so checking OSError first would
    # bucket every protocol-level SMTP error as a network problem and send an
    # operator looking at their firewall instead of their mail configuration.
    if isinstance(exc, smtplib.SMTPException):
        return "smtp_error"
    if isinstance(exc, OSError):
        return "network_error"
    return "unknown_error"


class SMTPEmailProvider:
    """Sends over SMTP using the standard library only.

    NOT VERIFIED AGAINST A LIVE SERVER by this repository. It is written against
    the documented `smtplib` / `email.message` surface and tested against an
    injected fake transport. Whether a given mail provider accepts it depends on
    credentials that are not shipped here, which is why the README says so
    instead of claiming delivery works.

    The password is read from the environment, held only on the instance, and
    never logged, never echoed, never returned, and never placed in an audit
    record. `__repr__` is overridden because a dataclass-style repr in a traceback
    is a very effective way to leak a credential into a log aggregator.
    """

    provider_name = PROVIDER_SMTP

    def __init__(self, *, host: str = "", port: int = 587, username: str = "",
                 password: str = "", sender: str = "", use_tls: bool = True,
                 timeout: int = 15, transport=None):
        self.host = host or ""
        self.port = int(port or 587)
        self.username = username or ""
        # Never rendered anywhere. See __repr__ below.
        self._password = password or ""
        self.sender = sender or username or ""
        self.use_tls = bool(use_tls)
        self.timeout = timeout
        # Injectable for tests. Nothing here opens a socket unless a real send
        # is attempted with real configuration.
        self._transport = transport

    def __repr__(self) -> str:
        # Explicitly redacted. A default repr would print `_password` verbatim
        # into any traceback that captures locals.
        return (f"SMTPEmailProvider(host={self.host!r}, port={self.port}, "
                f"username={'set' if self.username else 'unset'}, "
                f"password={'set' if self._password else 'unset'}, "
                f"use_tls={self.use_tls})")

    __str__ = __repr__

    def is_configured(self) -> bool:
        """Enough configuration to attempt a send.

        A host and a sender are the irreducible minimum. Username and password
        are NOT required: an internal relay on a trusted network legitimately
        accepts unauthenticated mail, and demanding credentials would force an
        operator to invent them. Whether the server accepts us is a question only
        a real send can answer.
        """
        return bool(self.host and self.sender)

    def missing(self) -> list[str]:
        """Which settings are absent, for an operator-facing warning."""
        gaps = []
        if not self.host:
            gaps.append("FRAUDSHIELD_SMTP_HOST")
        if not self.sender:
            gaps.append("FRAUDSHIELD_ALERT_FROM")
        return gaps

    def send_email(self, *, to, subject, body,
                   metadata: dict | None = None) -> SendResult:
        recipients = tuple(to)
        if not recipients:
            return SendResult(provider=self.provider_name, status=STATUS_SKIPPED,
                              recipient_count=0,
                              error="no recipients configured",
                              error_category="no_recipients")
        if not self.is_configured():
            return SendResult(
                provider=self.provider_name, status=STATUS_FAILED,
                recipient_count=len(recipients),
                error=f"SMTP is not configured: missing {', '.join(self.missing())}",
                error_category="not_configured")

        msg = EmailMessage()
        msg["From"] = self.sender
        msg["To"] = ", ".join(recipients)
        msg["Subject"] = subject
        # Identifies the sender as automation so a recipient's client does not
        # thread alerts into an unrelated conversation, and so mailing lists do
        # not auto-reply to them.
        msg["Auto-Submitted"] = "auto-generated"
        msg["X-FraudShield-Event"] = str((metadata or {}).get("event_type") or "")
        msg.set_content(body)

        try:
            self._deliver(msg, recipients)
        except Exception as exc:  # noqa: BLE001
            # Every transport failure lands here. The category is recorded; the
            # exception text is NOT, because it can carry the username, the
            # envelope or a server banner.
            return SendResult(
                provider=self.provider_name, status=STATUS_FAILED,
                recipient_count=len(recipients),
                error=f"SMTP delivery failed ({_error_category(exc)})",
                error_category=_error_category(exc))

        return SendResult(provider=self.provider_name, status=STATUS_SENT,
                          recipient_count=len(recipients))

    def _deliver(self, msg: EmailMessage, recipients: tuple[str, ...]) -> None:
        """The one place a socket is opened. Raises on any failure."""
        if self._transport is not None:
            self._transport.send_message(msg, self.sender, list(recipients))
            return

        with smtplib.SMTP(self.host, self.port, timeout=self.timeout) as s:
            s.ehlo()
            if self.use_tls:
                # Verified TLS, not opportunistic. `starttls()` with a default
                # context checks the certificate and hostname; passing an
                # unverified context here is the usual shortcut and it turns
                # transport security into decoration.
                s.starttls(context=ssl.create_default_context())
                s.ehlo()
            if self.username and self._password:
                s.login(self.username, self._password)
            s.send_message(msg, self.sender, list(recipients))


# ---------------------------------------------------------------------------
# message construction
# ---------------------------------------------------------------------------

def _rupees(amount) -> str:
    try:
        return f"Rs {float(amount):,.2f}"
    except (TypeError, ValueError):
        return "Rs (unknown)"


def _bullets(items, limit: int = 6) -> str:
    """Render a reason list. Empty renders as an explicit statement of absence
    rather than a blank gap, so a reader can tell "no reasons fired" from
    "reasons were lost"."""
    out = []
    for item in (items or [])[:limit]:
        if isinstance(item, dict):
            detail = item.get("detail") or item.get("code") or ""
            code = item.get("code") or ""
            sev = item.get("severity")
            label = f"{detail}" if detail else code
            out.append(f"  - {label}" + (f"  [{sev}]" if sev else ""))
        else:
            out.append(f"  - {item}")
    return "\n".join(out) if out else "  - (none recorded)"


def _console_link(base: str, path: str) -> str:
    if not base:
        return "(console URL not configured -- set FRAUDSHIELD_CONSOLE_URL)"
    return f"{base.rstrip('/')}{path}"


def _footer(console_url: str, path: str) -> str:
    return (
        f"\nInvestigate in the FraudShield console:\n"
        f"  {_console_link(console_url, path)}\n"
        f"\n{NOT_A_VERDICT}\n"
        f"\n{NO_CUSTOMER_CONTACT}\n"
    )


def build_transaction_alert(*, event_type: str, record: dict,
                            console_url: str = "") -> tuple[str, str]:
    """Subject and body for a MANUAL_REVIEW or BLOCK alert.

    Reads ONLY the stored transaction record. It never re-scores and never
    re-derives a risk number: the alerted values are by construction the exact
    ones the analyst queue and the audit trail were built from. Re-deriving them
    would let the email and the console disagree, and an analyst who has seen them
    disagree once will not trust either again.

    Deliberately absent from the body: card numbers, CVV, UPI ids, bank codes,
    wallet phone numbers, the customer's password or tokens. Email is the least
    controlled channel in the system -- it lands in mailboxes, on phones, in
    backups and in search indexes -- so it carries the least data that still makes
    the alert actionable.
    """
    txn_id = record.get("transaction_id") or "(unknown)"
    order_id = record.get("order_id") or "(none)"
    score = record.get("risk_score")
    decision = record.get("decision") or event_type

    if event_type == EVENT_BLOCK:
        subject = f"[FraudShield] High-risk transaction blocked - {txn_id}"
        headline = (
            "A transaction was REFUSED because its risk score crossed the "
            "configured block threshold.\n"
            "The payment was refused BEFORE the payment provider was contacted, "
            "so no money moved."
        )
    else:
        subject = f"[FraudShield] Transaction requires review - {txn_id}"
        headline = (
            "A transaction was routed to MANUAL REVIEW and is waiting in the "
            "analyst queue.\n"
            "The payment was not refused. A human decision is required."
        )

    sub = record.get("sub_scores") or {}
    body = (
        f"{headline}\n"
        f"\n"
        f"Event:            {event_type}\n"
        f"Decision:         {decision}\n"
        f"Risk score:       {score if score is not None else '(unknown)'} / 100\n"
        f"Transaction ID:   {txn_id}\n"
        f"Order ID:         {order_id}\n"
        f"Amount:           {_rupees(record.get('amount'))}\n"
        f"Payment method:   {record.get('payment_method') or '(unknown)'}\n"
        f"Settlement:       {record.get('settlement') or '(unknown)'}\n"
        f"Occurred at:      {record.get('created_at') or record.get('scored_at') or '(unknown)'}\n"
        f"Source:           {record.get('source') or 'storefront'}\n"
        f"\n"
        f"Layer contributions:\n"
        f"  ML       {sub.get('ml', '-')}\n"
        f"  Rules    {sub.get('rules', '-')}\n"
        f"  Network  {sub.get('network', '-')}\n"
        f"\n"
        f"Top risk reasons:\n"
        f"{_bullets(record.get('reason_codes'))}\n"
        f"\n"
        f"Fired rules:\n"
        f"{_bullets(record.get('fired_rules'))}\n"
        f"\n"
        f"Model version:    {record.get('model_version') or '(unknown)'}\n"
        f"Degraded mode:    {bool(record.get('degraded'))}"
        + ("   (ML layer unavailable; rules + network only)"
           if record.get("degraded") else "")
        + f"\n"
        f"Override applied: {record.get('override') or 'none'}\n"
        + _footer(console_url, "/admin")
    )
    return subject, body


def build_suspicious_ip_alert(*, flag: dict, window_minutes: int,
                              threshold: int,
                              console_url: str = "") -> tuple[str, str]:
    """Subject and body for a newly flagged address.

    The identifier in the body is the HMAC fingerprint the engine works with, not
    a raw IP address. That is not merely privacy hygiene: the raw address is never
    stored anywhere in this system, so there is nothing to reveal even if the
    mailbox is compromised -- and the fingerprint is what an analyst pastes into
    the console to pivot.
    """
    ip_hash = flag.get("ip_hash") or "(unknown)"
    subject = f"[FraudShield] Address flagged for repeated declines - {ip_hash[:16]}"
    body = (
        "An address crossed the failed-payment threshold and has been flagged "
        "for analyst attention.\n"
        "This is an OPERATIONAL flag. It is not part of the risk score and it "
        "labels no transaction and no customer.\n"
        f"\n"
        f"Event:              {EVENT_SUSPICIOUS_IP}\n"
        f"Address fingerprint: {ip_hash}\n"
        f"  (HMAC-SHA256 with a server-side pepper. The raw IP address is never "
        f"stored by FraudShield.)\n"
        f"Failed attempts:    {flag.get('failures_total', '(unknown)')}\n"
        f"Trigger:            {threshold} declines within {window_minutes} minutes\n"
        f"Distinct accounts:  {flag.get('accounts', '(unknown)')}\n"
        f"Flagged since:      {flag.get('since') or '(unknown)'}\n"
        f"Reason:             {flag.get('reason') or '(unknown)'}\n"
        f"\n"
        "Evidence available to analysts: every individual declined attempt from "
        "this address is stored and viewable, including amount, method, "
        "instrument fingerprint and the risk decision at the time.\n"
        + _footer(console_url, "/admin")
    )
    return subject, body


def build_promo_hold_alert(*, redemption: dict,
                           console_url: str = "") -> tuple[str, str]:
    """Subject and body for a held or denied cashback claim.

    The payout destination is deliberately omitted. It is a real UPI id or bank
    reference, an email is the least controlled channel in the system, and an
    analyst who needs it has the console.
    """
    rid = redemption.get("redemption_id") or "(unknown)"
    decision = redemption.get("decision") or "HOLD"
    subject = f"[FraudShield] Promotion claim held for review - {rid}"
    body = (
        f"A promotion claim was {decision} by the promo-abuse gate and needs a "
        f"human decision.\n"
        f"An override is the ONLY label source for this gate, so an analyst "
        f"decision here is how the rules are corrected.\n"
        f"\n"
        f"Event:            {EVENT_PROMO_HOLD}\n"
        f"Gate decision:    {decision}\n"
        f"Redemption ID:    {rid}\n"
        f"Promo code:       {redemption.get('promo_code') or '(unknown)'}\n"
        f"Value:            {_rupees(redemption.get('value'))}\n"
        f"Claimed at:       {redemption.get('created_at') or '(unknown)'}\n"
        f"Shared-IP exempt: {bool(redemption.get('shared_ip_exempt'))}\n"
        f"\n"
        f"Risk reasons:\n"
        f"{_bullets(redemption.get('reasons'))}\n"
        f"\n"
        f"Fired rules:\n"
        f"{_bullets(redemption.get('fired_rules'))}\n"
        f"\n"
        f"Entity evidence:\n"
        f"  Device fingerprint  {redemption.get('device_fp') or '(unknown)'}\n"
        f"  Address fingerprint {redemption.get('ip_hash') or '(unknown)'}\n"
        f"  (Payout destination is deliberately not included in email. It is "
        f"visible in the console.)\n"
        + _footer(console_url, "/admin")
    )
    return subject, body


# ---------------------------------------------------------------------------
# configuration and selection
# ---------------------------------------------------------------------------

def parse_recipients(raw: str) -> tuple[str, ...]:
    """Parse a recipient list safely.

    Accepts comma or semicolon separated addresses, trims whitespace, drops
    empties, de-duplicates while preserving order, and requires an '@'.

    A malformed entry is DROPPED rather than raising. A typo in one address must
    not stop the other recipients being alerted -- silence is the worse failure
    here, and the dropped count is reported in the provider status so the mistake
    is still visible.
    """
    if not raw or not isinstance(raw, str):
        return ()
    seen: dict[str, None] = {}
    for chunk in raw.replace(";", ",").split(","):
        addr = chunk.strip()
        if not addr or "@" not in addr or addr.startswith("@") or addr.endswith("@"):
            continue
        if len(addr) > 254:
            continue
        seen.setdefault(addr, None)
    return tuple(seen)


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def _env_int(name: str, default: int) -> int:
    try:
        return int(str(os.environ.get(name) or default).strip())
    except (TypeError, ValueError):
        return default


def email_config_from_env() -> dict:
    """Read notification configuration.

    Naming follows the convention already in this repository: FraudShield's own
    settings are FRAUDSHIELD_-prefixed. SMTP settings are prefixed too, unlike
    AWS_* and RAZORPAY_*, because there is no vendor-standard name for a generic
    SMTP relay -- so the project's own prefix is the least surprising choice.

    The password is read here and passed straight to the provider. It is never
    logged, never returned in a status dict, and never persisted.
    """
    return {
        "requested": (os.environ.get("FRAUDSHIELD_EMAIL_PROVIDER")
                      or PROVIDER_CONSOLE),
        "sender": os.environ.get("FRAUDSHIELD_ALERT_FROM", ""),
        "recipients_raw": os.environ.get("FRAUDSHIELD_ALERT_RECIPIENTS", ""),
        "host": os.environ.get("FRAUDSHIELD_SMTP_HOST", ""),
        "port": _env_int("FRAUDSHIELD_SMTP_PORT", 587),
        "username": os.environ.get("FRAUDSHIELD_SMTP_USERNAME", ""),
        "password": os.environ.get("FRAUDSHIELD_SMTP_PASSWORD", ""),
        "use_tls": _env_bool("FRAUDSHIELD_SMTP_USE_TLS", True),
        "console_url": os.environ.get("FRAUDSHIELD_CONSOLE_URL", ""),
    }


def resolve_email_provider(cfg: dict) -> tuple[object, dict]:
    """Pick a provider from explicit configuration.

    Returns (provider, status) where `status` is safe to publish on /health: it
    names the mode, whether it is configured, whether it is degraded, and how many
    recipients exist. It contains NO password, NO username and NO recipient
    addresses -- a count only, because a recipient list is an internal distribution
    list and /health is the least authenticated surface in the service.

    Selection is EXPLICIT. SMTP is never switched on merely because a host
    happens to be set: a stray value in a shell profile must not start mailing an
    unknown relay. And if SMTP is asked for but unusable, the service falls back
    to console and says so loudly rather than failing, because an alerting system
    that can take down checkout is worse than no alerting system.
    """
    requested = str(cfg.get("requested") or PROVIDER_CONSOLE).strip().lower()
    recipients = parse_recipients(cfg.get("recipients_raw", ""))
    supplied = len([c for c in str(cfg.get("recipients_raw") or "")
                    .replace(";", ",").split(",") if c.strip()])

    status = {
        "provider": PROVIDER_CONSOLE,
        "requested_provider": requested,
        "configured": True,
        "degraded": False,
        "recipient_count": len(recipients),
        # Surfaced so a typo in the recipient list is visible rather than silently
        # swallowing one analyst's address.
        "recipients_rejected": max(0, supplied - len(recipients)),
        "alerts_enabled": bool(recipients),
        "note": "",
    }

    def console(note: str, *, degraded: bool = False):
        status["provider"] = PROVIDER_CONSOLE
        status["degraded"] = degraded
        status["note"] = note
        return ConsoleEmailProvider(), status

    if not recipients:
        # Nothing to alert. Console still renders, so a demo works with no
        # configuration at all, but `alerts_enabled: false` is reported rather
        # than implying anyone is being notified.
        return console(
            "no FRAUDSHIELD_ALERT_RECIPIENTS configured; alerts are rendered to "
            "the console and delivered to nobody")

    if requested == PROVIDER_SMTP:
        smtp = SMTPEmailProvider(
            host=cfg.get("host", ""), port=cfg.get("port", 587),
            username=cfg.get("username", ""), password=cfg.get("password", ""),
            sender=cfg.get("sender", ""), use_tls=cfg.get("use_tls", True),
        )
        if smtp.is_configured():
            status["provider"] = PROVIDER_SMTP
            status["note"] = (
                "SMTP configured. Delivery has NOT been verified against a live "
                "mail server by this repository.")
            return smtp, status
        return console(
            f"FRAUDSHIELD_EMAIL_PROVIDER=smtp but {', '.join(smtp.missing())} "
            f"{'is' if len(smtp.missing()) == 1 else 'are'} unset. Falling back "
            f"to console: alerts are rendered, NOT emailed.",
            degraded=True)

    if requested != PROVIDER_CONSOLE:
        return console(
            f"unknown FRAUDSHIELD_EMAIL_PROVIDER={requested!r}; using console",
            degraded=True)

    return console("console provider; alerts are rendered, not transmitted")


def dedupe_key(event_type: str, subject_id: str) -> str:
    """The deterministic identity of one alertable event.

    A burst of card-testing declines is one situation, not forty. Keying on the
    event and its subject means the second through fortieth attempts to notify
    resolve to the same key and are suppressed -- which is the difference between
    an alert an analyst reads and a mailbox they mute.

    Lower-cased so a casing difference between two call sites cannot produce two
    keys for one event.
    """
    return f"{str(event_type).strip().lower()}:{str(subject_id).strip()}"
