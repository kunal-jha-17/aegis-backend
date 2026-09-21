"""
AEGIS — main.py
Orchestrator wiring Parts 1-4 together. Written during integration since no
part owned this file yet (Part 1's brief said main.py is written last, once
2-4 exist — that's now).

POST /v1/evaluate is the single end-to-end entry point:
  normalize -> hard gate -> (denied? synthesize BLOCK : full pipeline) ->
  create_review if FLAG -> log_audit -> broadcast_live -> return Decision
"""
from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import FastAPI
from pydantic import BaseModel

import part1_gateway
import part2_evidence
import part3_decision
import part4_human_audit
from shared_contracts import AegisError, Decision, enum_safe_dump

app = FastAPI(title="AEGIS")

app.include_router(part2_evidence.router)
app.include_router(part4_human_audit.router)


@app.on_event("startup")
async def _startup() -> None:
    # Both are idempotent / self-initializing on first real call too, but
    # doing it here means the FIRST /v1/evaluate request isn't slow.
    await part4_human_audit.init_db()
    # part2's init_evidence_service() needs live Moss credentials (MOSS_PROJECT_ID/
    # MOSS_PROJECT_KEY) — deliberately NOT called here so the app still boots
    # without them; it will lazy-init on the first real retrieve_evidence() call
    # instead, and fail there (clearly) if Moss isn't configured.


class EvaluateRequest(BaseModel):
    raw_call: Dict[str, Any]
    context: Dict[str, Any]
    framework: str = "openai"  # "openai" | "langchain"


_HTTP_STATUS_FALLBACK = 500


def _http_status_for(code: str) -> int:
    # Reuses Part 2's status map where it applies; anything else is a 500.
    return part2_evidence._HTTP_STATUS.get(code, _HTTP_STATUS_FALLBACK)  # noqa: SLF001 (intentional reuse)


from shared_contracts import ActionEnvelope
from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

@app.post("/v1/evaluate")
async def evaluate(envelope: ActionEnvelope) -> Dict[str, Any]:
    from fastapi import HTTPException
    try:
        hard_gate = await part1_gateway.run_hard_gate(envelope)
        if hard_gate.deny:
            decision = part3_decision.build_denied_decision(envelope, hard_gate)
        else:
            evidence = await part2_evidence.retrieve_evidence(envelope)
            risk = await part3_decision.compute_risk(envelope, evidence)
            impact = await part3_decision.compute_impact(envelope, risk)
            decision = await part3_decision.decide(envelope, evidence, hard_gate, risk, impact)

        review_id = None
        if decision.verdict.value == "FLAG":
            review = await part4_human_audit.create_review(decision, envelope)
            review_id = review.review_id

        await part4_human_audit.log_audit(envelope, decision)
        await part4_human_audit.broadcast_live(decision)
        out = enum_safe_dump(decision)
        if review_id:
            out["review_id"] = review_id
        return out
    except AegisError as e:
        raise HTTPException(status_code=_http_status_for(e.code), detail={"code": e.code, "message": e.message})


@app.get("/healthz")
async def healthz() -> Dict[str, str]:
    return {"status": "ok"}
