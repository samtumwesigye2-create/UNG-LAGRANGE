import hashlib
import hmac
import json
import os
import time
import urllib.error
import urllib.request

from fastapi import FastAPI, Header, HTTPException, Request

app = FastAPI(title="UNG-LAGRANGE", version="recovery-0.2")
MAX_CLOCK_SKEW_SECONDS = int(os.getenv("LAGRANGE_MAX_CLOCK_SKEW_SECONDS", "300"))
DELIVERY_TIMEOUT = float(os.getenv("LAGRANGE_DELIVERY_TIMEOUT", "8"))
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


def _service_registry() -> dict:
    registry = {}
    raw = os.getenv("LAGRANGE_BOOTSTRAP_SERVICES_JSON", "{}")
    try:
        data = json.loads(raw)
        if isinstance(data, dict):
            registry.update(data)
    except json.JSONDecodeError:
        pass

    # Safe production fallback: PULSAR can be supplied directly without
    # weakening the allow-listed registry model.
    pulsar = os.getenv("PULSAR_BASE_URL", "").rstrip("/")
    if pulsar and "UNG-PULSAR" not in registry:
        registry["UNG-PULSAR"] = pulsar
    return registry


def _destination_url(name: str) -> str | None:
    entry = _service_registry().get(name)
    if isinstance(entry, str):
        return entry.rstrip("/")
    if isinstance(entry, dict):
        value = entry.get("url") or entry.get("base_url")
        return value.rstrip("/") if isinstance(value, str) else None
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

    destination = str(envelope["to"])
    target = _destination_url(destination)
    if not target:
        raise HTTPException(status_code=404, detail="destination not registered")

    # PULSAR's established NEXUS ingress contract.
    path = "/v1/nexus/inbound" if destination == "UNG-PULSAR" else "/v1/lagrange/inbound"
    forwarded = json.dumps(envelope.get("payload", {}), separators=(",", ":"), ensure_ascii=False).encode()
    req = urllib.request.Request(
        target + path,
        data=forwarded,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "X-Lagrange-Source": x_lagrange_service,
            "X-Lagrange-Correlation-ID": str(envelope.get("idempotency_key", "")),
            "User-Agent": "UNG-LAGRANGE/recovery-0.2",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=DELIVERY_TIMEOUT) as response:
            response_body = response.read().decode()
            result = json.loads(response_body) if response_body else {}
            return {
                "status": "accepted",
                "destination": destination,
                "downstream_status": int(response.status),
                "result": result,
            }
    except urllib.error.HTTPError as exc:
        raise HTTPException(status_code=502, detail=f"downstream_http_{exc.code}")
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"delivery_failed:{type(exc).__name__}")
