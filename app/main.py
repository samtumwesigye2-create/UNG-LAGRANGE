import hashlib
import hmac
import json
import os
import time

from fastapi import FastAPI, Header, HTTPException, Request

app = FastAPI(title="UNG-LAGRANGE", version="recovery-0.2")
MAX_CLOCK_SKEW_SECONDS = int(os.getenv("LAGRANGE_MAX_CLOCK_SKEW_SECONDS", "300"))
_seen_nonces: dict[str, int] = {}


def _secret_registry() -> dict:
    merged = {}
    for name in ("LAGRANGE_SERVICE_SECRETS_JSON", "LAGRANGE_ADDITIONAL_SERVICE_SECRETS_JSON"):
        raw = os.getenv(name, "{}")
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if isinstance(data, dict):
            merged.update(data)
    return merged


def _resolve_secret(service: str, key_id: str) -> str | None:
    entry = _secret_registry().get(service)
    if isinstance(entry, str):
        return entry if key_id == "primary" else None
    if isinstance(entry, dict):
        value = entry.get(key_id)
        return value if isinstance(value, str) else None
    return None


def _reject_replay(nonce: str, now: int):
    expired = [n for n, expiry in _seen_nonces.items() if expiry < now]
    for n in expired:
        _seen_nonces.pop(n, None)
    if nonce in _seen_nonces:
        raise HTTPException(status_code=401, detail="replayed request")
    _seen_nonces[nonce] = now + MAX_CLOCK_SKEW_SECONDS


@app.get("/health")
def health():
    return {"service": "UNG-LAGRANGE", "status": "ok"}


@app.post("/v1/relay")
async def relay(
    request: Request,
    x_lagrange_service: str | None = Header(default=None),
    x_lagrange_key_id: str | None = Header(default=None),
    x_lagrange_timestamp: str | None = Header(default=None),
    x_lagrange_nonce: str | None = Header(default=None),
    x_lagrange_signature: str | None = Header(default=None),
):
    if not all((x_lagrange_service, x_lagrange_key_id, x_lagrange_timestamp,
                x_lagrange_nonce, x_lagrange_signature)):
        raise HTTPException(status_code=401, detail="missing LAGRANGE authentication")

    try:
        ts = int(x_lagrange_timestamp)
    except ValueError:
        raise HTTPException(status_code=401, detail="invalid timestamp")

    now = int(time.time())
    if abs(now - ts) > MAX_CLOCK_SKEW_SECONDS:
        raise HTTPException(status_code=401, detail="expired request")

    secret = _resolve_secret(x_lagrange_service, x_lagrange_key_id)
    if not secret:
        raise HTTPException(status_code=401, detail="unknown service or key")

    body = await request.body()
    body_hash = hashlib.sha256(body).hexdigest()
    canonical = "\n".join(("POST", "/v1/relay", x_lagrange_timestamp,
                            x_lagrange_nonce, body_hash))
    expected = hmac.new(secret.encode(), canonical.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, x_lagrange_signature):
        raise HTTPException(status_code=401, detail="invalid signature")

    _reject_replay(x_lagrange_nonce, now)

    try:
        envelope = json.loads(body)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="invalid JSON")

    if not isinstance(envelope, dict) or not envelope.get("from") or not envelope.get("to"):
        raise HTTPException(status_code=422, detail="invalid relay envelope")
    if envelope["from"] != x_lagrange_service:
        raise HTTPException(status_code=403, detail="service identity mismatch")

    # Authentication contract is restored. Delivery remains fail-closed until
    # the recovered registry/destination transport is acceptance-tested.
    raise HTTPException(status_code=503, detail="authenticated; delivery recovery pending")
