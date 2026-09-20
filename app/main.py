import os
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

app = FastAPI(title="UNG-LAGRANGE", version="recovery-0.1")

class RelayEnvelope(BaseModel):
    destination: str
    payload: dict
    correlation_id: str | None = None

@app.get("/health")
def health():
    return {"service": "UNG-LAGRANGE", "status": "ok"}

@app.post("/v1/relay")
def relay(envelope: RelayEnvelope, authorization: str | None = Header(default=None)):
    # Recovery baseline deliberately fails closed until the exact production
    # credential contract is restored and acceptance-tested.
    if not authorization:
        raise HTTPException(status_code=401, detail="authentication required")
    raise HTTPException(status_code=503, detail="relay recovery baseline: delivery disabled")
