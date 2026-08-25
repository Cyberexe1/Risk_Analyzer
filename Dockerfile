# Serving image. Carries backend.py and the model artifacts, nothing else.
#
# Deliberately excluded: ml/generate_dataset.py, ml/train.py, ml/evaluate.py,
# ml/scoring.py, tests/, and the 20 MB dataset CSV. None of it runs in production,
# and shipping a dataset generator into a payment-path container is a needless
# increase in image size and attack surface.

FROM python:3.13-slim

WORKDIR /srv

# Runtime deps only -- no scikit-learn (see requirements-serve.txt).
COPY requirements-serve.txt .
RUN pip install --no-cache-dir -r requirements-serve.txt

# The trained model, the isotonic calibrator knots, and the feature spec.
COPY ml/artifacts/model.json ml/artifacts/calibrator.json \
     ml/artifacts/feature_spec.json /srv/artifacts/

COPY backend.py .

ENV FRAUDSHIELD_ARTIFACTS=/srv/artifacts \
    FRAUDSHIELD_WARM_ROWS=0 \
    PYTHONUNBUFFERED=1

# WARM_ROWS defaults to 0 here because the dataset CSV is not in the image. In a
# real deployment the store is warmed from DynamoDB, not from a file -- and that
# adapter is not built yet, so a fresh container starts with a cold entity graph
# and will under-score network risk until traffic accumulates.

# Runs unprivileged. The service needs no write access to anything.
RUN useradd --create-home --shell /usr/sbin/nologin fraudshield \
    && chown -R fraudshield:fraudshield /srv
USER fraudshield

EXPOSE 8000

# SECURITY: set FRAUDSHIELD_API_KEY at run time. If it is unset the two
# service-to-service risk endpoints are open, and the service says so on startup.
#
# Per-user auth, role gating and login rate limiting DO exist now: JWT access
# tokens with an httpOnly refresh cookie, Argon2id credentials, and require_role
# on every admin route. Also set, or accept the consequences printed at boot:
#   FRAUDSHIELD_JWT_SECRET      unset -> ephemeral, every restart drops sessions
#   FRAUDSHIELD_IP_PEPPER       unset -> ephemeral, entity fingerprints reset
#   FRAUDSHIELD_COOKIE_SECURE   must be true behind HTTPS
#   FRAUDSHIELD_WEBHOOK_SECRET  unset -> /v1/webhooks/payment refuses with 503
# Still absent: email verification, password reset, MFA.
HEALTHCHECK --interval=30s --timeout=3s --start-period=20s \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health').status==200 else 1)"

# --forwarded-allow-ips="" is REQUIRED, not cosmetic. uvicorn otherwise rewrites
# request.client.host from X-Forwarded-For for any loopback caller, which would let
# a request choose its own IP and walk straight past ip_concentration, ring
# detection and the promo gate's IP signals. If a real reverse proxy is added, set
# FRAUDSHIELD_TRUSTED_PROXIES to its address instead of re-enabling this.
CMD ["uvicorn", "backend:app", "--host", "0.0.0.0", "--port", "8000", \
     "--forwarded-allow-ips="]

