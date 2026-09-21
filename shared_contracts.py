"""
AEGIS — Shared Contract
=======================
IDENTICAL across all 4 backend parts. Never redefine these classes locally
in any part module — always `from shared_contracts import ...`.

MERGE NOTE: Parts 2, 3, and 4 each submitted their own copy of this file.
All three were structurally identical (same fields, same types) with only
cosmetic differences (blank lines, comment wording, one-line vs multi-line
class bodies). This is the single canonical version going forward.

One real gap found and fixed here: Part 1's code does
`from shared_contracts import ... enum_safe_dump` but no submitted copy of
this file defined that function — it would have failed on import. Added
below as a thin wrapper so Part 1's file did not need to change at all.
"""
from enum import Enum
from typing import Optional, List, Dict, Any
from pydantic import BaseModel


class AegisError(Exception):
    """Single exception type for the whole backend. Never raise a bare Exception.

    MERGE NOTE: Part 2/4's copy formatted the message as "CODE: message";
    Part 3's copy formatted it as "[CODE] message". Cosmetic only — .code
    and .message are identical either way — but picking ONE matters if
    anything ever asserts on str(exception). Standardized on Part 3's
    "[CODE] message" form below.
    """

    def __init__(self, code: str, message: str):
        self.code = code
        self.message = message
        super().__init__(f"[{code}] {message}")


class Verdict(str, Enum):
    ALLOW = "ALLOW"
    FLAG = "FLAG"
    BLOCK = "BLOCK"


class OperationClass(str, Enum):
    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    SEND = "send"
    APPROVE = "approve"
    EXPORT = "export"
    PERMISSION_CHANGE = "permission_change"


class ActionEnvelope(BaseModel):
    request_id: str
    timestamp: str
    tenant_id: str
    session_id: str
    agent_id: str
    agent_version: str
    framework: str
    principal_id: str
    tool_name: str
    operation_class: OperationClass
    target_resource: str
    arguments: Dict[str, Any]
    user_intent: str
    credential_scope: str
    reversibility: str  # "reversible" | "irreversible" | "partial"
    estimated_amount: Optional[float] = None
    parent_action_id: Optional[str] = None
    trace_id: str


class EvidenceItem(BaseModel):
    id: str
    text: str
    source: str
    freshness_ts: str
    score: float


class EvidenceBundle(BaseModel):
    policy_matches: List[EvidenceItem]
    precedent_matches: List[EvidenceItem]


class HardGateResult(BaseModel):
    passed: bool
    deny: bool
    reason_codes: List[str]


class RiskAssessment(BaseModel):
    risk_score: float
    confidence: float
    reversibility: str
    anomaly_flags: List[str]


class ImpactEstimate(BaseModel):
    estimated_exposure: Optional[float]
    calculation: str
    currency: str = "INR"


class Decision(BaseModel):
    request_id: str
    verdict: Verdict
    reason_codes: List[str]
    human_explanation: str
    policy_ids: List[str]
    evidence_ids: List[str]
    precedent_ids: List[str]
    risk_score: float
    confidence: float
    estimated_exposure: Optional[float]
    calculation: str
    required_approval: bool
    latency_ms: float
    policy_version: str
    decision_hash: str
    expires_at: Optional[str]
    replay_token: str


class PrecedentScope(BaseModel):
    tenant_id: str
    agent_id: str
    tool_name: str
    resource_class: str
    argument_conditions: Dict[str, Any]


class PrecedentRecord(BaseModel):
    precedent_id: str
    scope: PrecedentScope
    outcome: str  # "approved" | "rejected"
    reviewer_id: str
    reason: str
    created_at: str
    expires_at: Optional[str]
    revoked: bool = False


class ReviewRecord(BaseModel):
    review_id: str
    envelope: ActionEnvelope
    decision: Decision
    status: str  # "pending" | "resolved"
    created_at: str


def enum_safe_dump(obj: BaseModel) -> dict:
    """Pydantic v2 model -> plain JSON-safe dict, enums rendered via .value.

    Added during integration: Part 1's file imports this name but no part's
    submitted shared_contracts.py defined it. It's just an alias for the
    pattern Part 3 already used locally (`_stable_serialize`) and Part 2/4
    use inline (`model_dump(mode="json")`) — centralized here so all 4
    parts can call the same helper instead of each re-implementing it.
    """
    return obj.model_dump(mode="json")
