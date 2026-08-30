"""Test-session guards that must run BEFORE `import backend`.

WHY THIS FILE EXISTS
--------------------
`.env` now configures real Gmail SMTP so the demo can actually email an analyst.
`backend.py` loads `.env` at import time and `notifications.email_config_from_env()`
reads it once into `_EMAIL_CFG`, so without this file the suite would come up with
a live `SMTPEmailProvider` and a real recipient -- and every test that produces a
BLOCK or MANUAL_REVIEW would send a real email. That is hundreds of messages per
run, sent to a real mailbox, from a test suite.

pytest imports conftest.py before any test module, which is the only window in
which this can be fixed: once `backend` is imported, `_EMAIL_CFG` is already built.

Individual tests that WANT to exercise SMTP already inject a provider directly --
`backend.STATE["email_provider"] = nf.SMTPEmailProvider(transport=FakeTransport())`
-- so nothing here reduces coverage. It only removes the ambient configuration that
would otherwise open a socket.

The same reasoning is why CI fails outright if FRAUDSHIELD_SMTP_PASSWORD,
FRAUDSHIELD_SMTP_HOST or FRAUDSHIELD_ALERT_RECIPIENTS is present in the
environment: a suite that can reach an external service stops meaning what it says
when it goes green.
"""
from __future__ import annotations

import os

# Every variable that could turn the notification path into a live transport.
# Cleared, not overwritten, so `resolve_email_provider` takes its documented
# console default and reports `alerts_enabled: false`.
_EMAIL_VARS = (
    "FRAUDSHIELD_EMAIL_PROVIDER",
    "FRAUDSHIELD_ALERT_FROM",
    "FRAUDSHIELD_ALERT_RECIPIENTS",
    "FRAUDSHIELD_SMTP_HOST",
    "FRAUDSHIELD_SMTP_PORT",
    "FRAUDSHIELD_SMTP_USERNAME",
    "FRAUDSHIELD_SMTP_PASSWORD",
    "FRAUDSHIELD_SMTP_USE_TLS",
)

for _name in _EMAIL_VARS:
    os.environ.pop(_name, None)

# Belt and braces: `_load_dotenv()` in backend.py only sets a variable that is not
# already present, so seeding an explicit console value means a later .env read
# cannot reintroduce SMTP even if the pop above were somehow bypassed.
os.environ["FRAUDSHIELD_EMAIL_PROVIDER"] = "console"
os.environ["FRAUDSHIELD_ALERT_RECIPIENTS"] = ""

# The demo trigger is off unless a test opts in, matching production. Tests that
# need it set `backend.DEMO_MODE` directly rather than relying on the environment.
os.environ["FRAUDSHIELD_DEMO_MODE"] = "false"


def pytest_report_header(config) -> str:
    """State the guard in the test header, so a green run says what it covered."""
    del config
    return ("email: console forced by tests/conftest.py -- no SMTP socket is "
            "opened and no real recipient is configured")
