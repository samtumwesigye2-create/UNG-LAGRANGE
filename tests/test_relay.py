import hashlib
import hmac
import json
import time

from fastapi.testclient import TestClient
from app.main import app, _seen_nonces

client = TestClient(app)

def signed(body: bytes, secret="shared-secret", nonce="n-1"):
    ts = str(int(time.time()))
    digest = hashlib.sha256(body).hexdigest()
    canonical = "\n".join(("POST", "/v1/relay", ts, nonce, digest))
    sig = hmac.new(secret.encode(), canonical.encode(), hashlib.sha256).hexdigest()
    return {
        "Content-Type": "application/json",
        "X-Lagrange-Service": "UNG-NEXUS",
        "X-Lagrange-Key-ID": "primary",
        "X-Lagrange-Timestamp": ts,
        "X-Lagrange-Nonce": nonce,
        "X-Lagrange-Signature": sig,
    }

def envelope():
    return {
        "from": "UNG-NEXUS",
        "to": "UNG-PULSAR",
        "payload": {"message_id": "m1", "payload": {"probe": True}},
        "idempotency_key": "m1",
    }

def test_missing_auth_rejected():
    assert client.post("/v1/relay", json=envelope()).status_code == 401

def test_bad_signature_rejected(monkeypatch):
    monkeypatch.setenv("LAGRANGE_SERVICE_SECRETS_JSON", '{"UNG-NEXUS":{"primary":"shared-secret"}}')
    body = json.dumps(envelope(), separators=(",", ":")).encode()
    headers = signed(body)
    headers["X-Lagrange-Signature"] = "bad"
    assert client.post("/v1/relay", content=body, headers=headers).status_code == 401

def test_replay_blocked(monkeypatch):
    monkeypatch.setenv("LAGRANGE_SERVICE_SECRETS_JSON", '{"UNG-NEXUS":{"primary":"shared-secret"}}')
    monkeypatch.setenv("LAGRANGE_BOOTSTRAP_SERVICES_JSON", "{}")
    _seen_nonces.clear()
    body = json.dumps(envelope(), separators=(",", ":")).encode()
    headers = signed(body, nonce="replay")
    first = client.post("/v1/relay", content=body, headers=headers)
    second = client.post("/v1/relay", content=body, headers=headers)
    assert first.status_code == 404
    assert second.status_code == 401

def test_registry_routes_nexus_to_pulsar(monkeypatch):
    monkeypatch.setenv("LAGRANGE_SERVICE_SECRETS_JSON", '{"UNG-NEXUS":{"primary":"shared-secret"}}')
    monkeypatch.setenv("LAGRANGE_BOOTSTRAP_SERVICES_JSON", '{"UNG-PULSAR":"https://pulsar.example"}')
    _seen_nonces.clear()

    class Response:
        status = 202
        def read(self): return b'{"status":"accepted"}'
        def __enter__(self): return self
        def __exit__(self, *args): pass

    seen = {}
    def fake_open(req, timeout):
        seen["url"] = req.full_url
        seen["body"] = req.data
        return Response()

    monkeypatch.setattr("app.main.urllib.request.urlopen", fake_open)
    body = json.dumps(envelope(), separators=(",", ":")).encode()
    response = client.post("/v1/relay", content=body, headers=signed(body, nonce="route"))
    assert response.status_code == 200
    assert seen["url"] == "https://pulsar.example/v1/nexus/inbound"
    assert json.loads(seen["body"])["message_id"] == "m1"
    assert response.json()["downstream_status"] == 202
