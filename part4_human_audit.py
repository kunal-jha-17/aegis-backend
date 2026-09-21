"""
TEAM CRYPTIX — AEGIS BACKEND — PART 4 of 4
Human Gate, Audit, Replay & Shadow Mode

INTEGRATION SEAM — FIXED. Part 4's session explicitly flagged that it had
not seen Parts 1-3's briefs and was guessing signatures. Below are the
concrete mismatches found by diffing against the real Part 2 and Part 3
files, all fixed in the four `_p*`/`_run_pipeline_read_only` functions and
`resolve_review`. Everything else in this file is unchanged from submission.

  1. Module names: PART_MODULES pointed at "part1"/"part2"/"part3" — the
     real files are part1_gateway.py / part2_evidence.py / part3_decision.py.

  2. part2.write_precedent: assumed `(scope, outcome, reviewer_id, reason)`.
     Real signature is `(envelope, outcome, reviewer_id, reason, scope)` —
     it needs the full envelope (it validates scope against it). The old
     call would have raised TypeError immediately on the first FLAG
     approval, which would have surfaced during the very first demo run —
     but better to catch it now.

  3. part2.revoke_precedent: assumed `(precedent_id, reviewer_id, reason)`.
     Real signature is `(precedent_id)` only — it doesn't record who
     revoked something or why (Part 2 didn't build that). Fixed the call;
     flagging the information loss below rather than hiding it.

  4. part3.compute_risk: assumed `(envelope, evidence, hard_gate)`.
     Real signature is `(envelope, evidence)` — no hard_gate parameter.

  5. part3.compute_impact: assumed `(envelope)`.
     Real signature is `(envelope, risk)` — needs the RiskAssessment.

  6. part3.decide: assumed `(envelope, hard_gate, evidence, risk, impact)`.
     Real signature is `(envelope, evidence, hard_gate, risk, impact)` —
     evidence and hard_gate were in the wrong order. This one would NOT
     have crashed loudly — both are Pydantic objects, so it would have run
     and silently produced wrong verdicts in shadow_simulate. This was the
     most dangerous bug of the four, precisely because it wouldn't have
     thrown an exception.

  7. _scope_from_envelope built exact-match argument_conditions (a literal
     copy of every argument). Since Part 2's precedent matcher performs
     exact equality when no `$operator` dict is given, a precedent from
     "approve this refund" would only ever re-match a FUTURE request with
     the identical order_id and identical amount — never a "similar"
     request. That breaks the demo's core moment (approve once -> a
     similar-but-not-identical request should match the new precedent).
     Fixed to build a `{"$lte": amount}` bound on any numeric amount field,
     exact-match on everything else — see the new version below.

Everything else (audit log, replay, WS live feed, agent behavior stats,
API router) is unchanged from submission and did not need fixing.
"""
import asyncio
import hashlib
import importlib
import inspect
import json
import os
import re
import sqlite3
import threading
import uuid
from collections import Counter
from contextlib import closing
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query, WebSocket, WebSocketDisconnect
from pydantic import BaseModel

from shared_contracts import (
    ActionEnvelope,
    AegisError,
    Decision,
    EvidenceBundle,
    EvidenceItem,
    HardGateResult,
    ImpactEstimate,
    OperationClass,
    PrecedentRecord,
    PrecedentScope,
    ReviewRecord,
    RiskAssessment,
    Verdict,
)

DB_PATH = "./data/aegis.db"
VALID_OUTCOMES = ("approved", "rejected")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# =============================================================================
# INTEGRATION SEAM — fixed to match the real Part 1/2/3 modules.
# =============================================================================
PART_MODULES = {"part1": "part1_gateway", "part2": "part2_evidence", "part3": "part3_decision"}

_INJECTED: Dict[str, Any] = {}
_DEFAULT_MOCKS: Dict[str, Any] = {}


def use_integration_modules(part1: Any = None, part2: Any = None, part3: Any = None) -> None:
    for name, mod in (("part1", part1), ("part2", part2), ("part3", part3)):
        if mod is not None:
            _INJECTED[name] = mod


def reset_integration_modules() -> None:
    _INJECTED.clear()


def _mod(name: str) -> Any:
    if name in _INJECTED:
        return _INJECTED[name]
    if os.environ.get("AEGIS_PART4_MOCKS") == "1":
        if not _DEFAULT_MOCKS:
            _DEFAULT_MOCKS.update({"part1": MockPart1(), "part2": MockPart2(), "part3": MockPart3()})
        return _DEFAULT_MOCKS[name]
    try:
        return importlib.import_module(PART_MODULES[name])
    except ImportError as e:
        raise AegisError(
            "INTEGRATION_MODULE_MISSING",
            f"Cannot import '{PART_MODULES[name]}' for {name}: {e}. "
            f"Set PART_MODULES, or AEGIS_PART4_MOCKS=1 for standalone runs.",
        ) from e


async def _call(fn, *args, **kwargs):
    res = fn(*args, **kwargs)
    if inspect.isawaitable(res):
        res = await res
    return res


async def _guarded(part: str, fn_name: str, *args, **kwargs):
    fn = getattr(_mod(part), fn_name)
    try:
        return await _call(fn, *args, **kwargs)
    except AegisError:
        raise
    except Exception as e:
        raise AegisError(f"{part.upper()}_CALL_FAILED", f"{part}.{fn_name} failed: {e!r}") from e


# FIXED — real signature: write_precedent(envelope, outcome, reviewer_id, reason, scope)
async def _p2_write_precedent(envelope: ActionEnvelope, outcome: str, reviewer_id: str, reason: str,
                              scope: PrecedentScope) -> PrecedentRecord:
    rec = await _guarded("part2", "write_precedent", envelope, outcome, reviewer_id, reason, scope)
    return rec if isinstance(rec, PrecedentRecord) else PrecedentRecord.model_validate(rec)


# FIXED — real signature: revoke_precedent(precedent_id) only. reviewer_id/reason are
# accepted here so resolve_review's call site doesn't change shape, but they are NOT
# passed through to Part 2 (it has nowhere to store them) — logged locally instead so
# the information isn't silently dropped.
async def _p2_revoke_precedent(precedent_id: str, reviewer_id: str, reason: str) -> Any:
    print(f"[part4_human_audit] revoking precedent {precedent_id} "
          f"(by {reviewer_id}: {reason}) — Part 2's revoke_precedent does not store who/why")
    return await _guarded("part2", "revoke_precedent", precedent_id)


# FIXED — real signatures:
#   part1.run_hard_gate(envelope) -> HardGateResult                (unchanged, was already right)
#   part2.retrieve_evidence(envelope) -> EvidenceBundle             (unchanged, was already right)
#   part3.compute_risk(envelope, evidence) -> RiskAssessment        (dropped hard_gate arg)
#   part3.compute_impact(envelope, risk) -> ImpactEstimate          (added risk arg)
#   part3.decide(envelope, evidence, hard_gate, risk, impact)       (evidence/hard_gate swapped back)
async def _run_pipeline_read_only(envelope: ActionEnvelope) -> Decision:
    hard_gate = await _guarded("part1", "run_hard_gate", envelope)
    evidence = await _guarded("part2", "retrieve_evidence", envelope)
    risk = await _guarded("part3", "compute_risk", envelope, evidence)
    impact = await _guarded("part3", "compute_impact", envelope, risk)
    decision = await _guarded("part3", "decide", envelope, evidence, hard_gate, risk, impact)
    return decision if isinstance(decision, Decision) else Decision.model_validate(decision)


# =============================================================================
# STORAGE (shared SQLite file)
# =============================================================================
_SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_log (
    seq                INTEGER PRIMARY KEY AUTOINCREMENT,
    logged_at          TEXT NOT NULL,
    mode               TEXT NOT NULL,
    request_id         TEXT NOT NULL,
    decision_hash      TEXT NOT NULL,
    policy_version     TEXT NOT NULL,
    tenant_id          TEXT NOT NULL,
    agent_id           TEXT NOT NULL,
    tool_name          TEXT NOT NULL,
    verdict            TEXT NOT NULL,
    risk_score         REAL,
    confidence         REAL,
    latency_ms         REAL,
    estimated_exposure REAL,
    reason_codes_json  TEXT NOT NULL,
    envelope_json      TEXT NOT NULL,
    decision_json      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_audit_request ON audit_log(request_id, seq);
CREATE INDEX IF NOT EXISTS ix_audit_hash    ON audit_log(decision_hash, seq);
CREATE INDEX IF NOT EXISTS ix_audit_agent   ON audit_log(agent_id, mode, seq);
CREATE TRIGGER IF NOT EXISTS audit_log_no_update BEFORE UPDATE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_log_no_delete BEFORE DELETE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;

CREATE TABLE IF NOT EXISTS reviews (
    review_id                TEXT PRIMARY KEY,
    request_id               TEXT NOT NULL,
    tenant_id                TEXT NOT NULL,
    agent_id                 TEXT NOT NULL,
    envelope_json            TEXT NOT NULL,
    decision_json            TEXT NOT NULL,
    status                   TEXT NOT NULL,
    created_at               TEXT NOT NULL,
    outcome                  TEXT,
    reviewer_id              TEXT,
    reason                   TEXT,
    resolved_at              TEXT,
    precedent_id             TEXT,
    resolved_decision_json   TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_reviews_one_pending
    ON reviews(request_id) WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS ix_reviews_agent ON reviews(agent_id, status);
"""

_schema_lock = threading.Lock()
_schema_ready_for: Optional[str] = None


def _connect() -> sqlite3.Connection:
    os.makedirs(os.path.dirname(os.path.abspath(DB_PATH)), exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=15000")
    return conn


def _ensure_schema_sync() -> None:
    global _schema_ready_for
    if _schema_ready_for == DB_PATH:
        return
    with _schema_lock:
        if _schema_ready_for == DB_PATH:
            return
        with closing(_connect()) as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(_SCHEMA)
            conn.commit()
        _schema_ready_for = DB_PATH


async def init_db() -> None:
    await asyncio.to_thread(_ensure_schema_sync)


def _insert_audit(conn: sqlite3.Connection, envelope: ActionEnvelope, decision: Decision, mode: str) -> None:
    conn.execute(
        """INSERT INTO audit_log
           (logged_at, mode, request_id, decision_hash, policy_version, tenant_id, agent_id,
            tool_name, verdict, risk_score, confidence, latency_ms, estimated_exposure,
            reason_codes_json, envelope_json, decision_json)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            _now(), mode, decision.request_id, decision.decision_hash, decision.policy_version,
            envelope.tenant_id, envelope.agent_id, envelope.tool_name,
            Verdict(decision.verdict).value, decision.risk_score, decision.confidence,
            decision.latency_ms, decision.estimated_exposure,
            json.dumps(decision.reason_codes), envelope.model_dump_json(), decision.model_dump_json(),
        ),
    )


async def _append_audit(envelope: ActionEnvelope, decision: Decision, mode: str) -> None:
    def _work() -> None:
        _ensure_schema_sync()
        with closing(_connect()) as conn:
            with conn:
                _insert_audit(conn, envelope, decision, mode)

    try:
        await asyncio.to_thread(_work)
    except AegisError:
        raise
    except Exception as e:
        raise AegisError("AUDIT_WRITE_FAILED", f"could not append audit row: {e!r}") from e


async def log_audit(envelope: ActionEnvelope, decision: Decision) -> None:
    await _append_audit(envelope, decision, "live")


async def get_decision(request_id: str, include_shadow: bool = False) -> Decision:
    def _work() -> Optional[str]:
        _ensure_schema_sync()
        sql = "SELECT decision_json FROM audit_log WHERE request_id=?"
        if not include_shadow:
            sql += " AND mode != 'shadow'"
        sql += " ORDER BY seq DESC LIMIT 1"
        with closing(_connect()) as conn:
            row = conn.execute(sql, (request_id,)).fetchone()
            return row["decision_json"] if row else None

    text = await asyncio.to_thread(_work)
    if text is None:
        raise AegisError("DECISION_NOT_FOUND", f"no decision recorded for request_id '{request_id}'")
    return Decision.model_validate_json(text)


def _row_to_review(row: sqlite3.Row) -> ReviewRecord:
    return ReviewRecord(
        review_id=row["review_id"],
        envelope=ActionEnvelope.model_validate_json(row["envelope_json"]),
        decision=Decision.model_validate_json(row["decision_json"]),
        status=row["status"],
        created_at=row["created_at"],
    )


async def create_review(decision: Decision, envelope: ActionEnvelope) -> ReviewRecord:
    if Verdict(decision.verdict) != Verdict.FLAG:
        raise AegisError("REVIEW_NOT_FLAG", f"reviews are only created for FLAG decisions, got {Verdict(decision.verdict).value}")
    if decision.request_id != envelope.request_id:
        raise AegisError("REQUEST_ID_MISMATCH", "decision.request_id does not match envelope.request_id")

    def _work() -> ReviewRecord:
        _ensure_schema_sync()
        review_id = f"rev_{uuid.uuid4().hex}"
        with closing(_connect()) as conn:
            try:
                with conn:
                    conn.execute(
                        """INSERT INTO reviews (review_id, request_id, tenant_id, agent_id,
                               envelope_json, decision_json, status, created_at)
                           VALUES (?,?,?,?,?,?, 'pending', ?)""",
                        (review_id, envelope.request_id, envelope.tenant_id, envelope.agent_id,
                         envelope.model_dump_json(), decision.model_dump_json(), _now()),
                    )
            except sqlite3.IntegrityError:
                row = conn.execute(
                    "SELECT * FROM reviews WHERE request_id=? AND status='pending'", (envelope.request_id,)
                ).fetchone()
                if row is None:
                    raise
                return _row_to_review(row)
            return _row_to_review(conn.execute("SELECT * FROM reviews WHERE review_id=?", (review_id,)).fetchone())

    try:
        return await asyncio.to_thread(_work)
    except AegisError:
        raise
    except Exception as e:
        raise AegisError("REVIEW_CREATE_FAILED", repr(e)) from e


def _resource_class(target_resource: str) -> str:
    """'invoices/INV-123' -> 'invoices'. NOTE: kept case-sensitive here (unlike
    Part 2's lowercased derive_resource_class) but this is safe — Part 2's
    write_precedent recomputes and OVERWRITES resource_class with its own
    canonical (lowercased) version before storing, so whatever case this
    function returns never actually persists. Left as-is rather than
    "fixed" since it causes no functional bug, just noting it for clarity."""
    t = (target_resource or "").strip().lstrip("/")
    return re.split(r"[/:#?]", t, maxsplit=1)[0] or (target_resource or "")


_NUMERIC_AMOUNT_KEYS = {"amount", "estimated_amount", "value", "row_count"}


def _scope_from_envelope(env: ActionEnvelope) -> PrecedentScope:
    conditions: Dict[str, Any] = {}
    for k, v in env.arguments.items():
        if k.endswith("_id"):
            continue  # order_id, ticket_id, customer_id etc. never go in the pattern
        if k in _NUMERIC_AMOUNT_KEYS and isinstance(v, (int, float)) and not isinstance(v, bool):
            conditions[k] = {"$lte": v}
        else:
            conditions[k] = v
    return PrecedentScope(
        tenant_id=env.tenant_id,
        agent_id=env.agent_id,
        tool_name=env.tool_name,
        resource_class=_resource_class(env.target_resource),
        argument_conditions=conditions,
    )


def _compute_decision_hash(d: Decision) -> str:
    payload = d.model_dump(mode="json", exclude={"decision_hash", "replay_token"})
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()


def _apply_resolution(original: Decision, outcome: str, reviewer_id: str, reason: str,
                      precedent_id: Optional[str]) -> Decision:
    approved = outcome == "approved"
    precedent_ids = list(original.precedent_ids)
    if approved and precedent_id:
        precedent_ids.append(precedent_id)
    updated = original.model_copy(update={
        "verdict": Verdict.ALLOW if approved else Verdict.BLOCK,
        "reason_codes": list(original.reason_codes) + ["HUMAN_APPROVED" if approved else "HUMAN_REJECTED"],
        "human_explanation": f"{original.human_explanation} | Human review {outcome} by {reviewer_id}: {reason}",
        "precedent_ids": precedent_ids,
        "required_approval": False,
    })
    return updated.model_copy(update={"decision_hash": _compute_decision_hash(updated)})


_resolve_lock = asyncio.Lock()


async def resolve_review(review_id: str, outcome: str, reviewer_id: str, reason: str) -> Decision:
    if outcome not in VALID_OUTCOMES:
        raise AegisError("INVALID_OUTCOME", f"outcome must be one of {list(VALID_OUTCOMES)}, got '{outcome}'")
    if not (reviewer_id or "").strip() or not (reason or "").strip():
        raise AegisError("INVALID_INPUT", "reviewer_id and reason are required")

    async with _resolve_lock:
        def _load() -> Optional[sqlite3.Row]:
            _ensure_schema_sync()
            with closing(_connect()) as conn:
                return conn.execute("SELECT * FROM reviews WHERE review_id=?", (review_id,)).fetchone()

        row = await asyncio.to_thread(_load)
        if row is None:
            raise AegisError("REVIEW_NOT_FOUND", f"no review '{review_id}'")

        envelope = ActionEnvelope.model_validate_json(row["envelope_json"])
        original = Decision.model_validate_json(row["decision_json"])
        precedent_id: Optional[str] = row["precedent_id"]

        if row["status"] == "resolved":
            if row["outcome"] == outcome:
                return Decision.model_validate_json(row["resolved_decision_json"])
            if row["outcome"] == "approved" and outcome == "rejected":
                if precedent_id:
                    await _p2_revoke_precedent(precedent_id, reviewer_id, reason)
            else:
                raise AegisError("REVIEW_ALREADY_RESOLVED",
                                 f"review '{review_id}' was already resolved as '{row['outcome']}'")

        if outcome == "approved":
            # FIXED: real write_precedent needs the envelope too, not just scope.
            precedent = await _p2_write_precedent(envelope, "approved", reviewer_id, reason,
                                                  _scope_from_envelope(envelope))
            precedent_id = precedent.precedent_id

        resolved = _apply_resolution(original, outcome, reviewer_id, reason,
                                     precedent_id if outcome == "approved" else None)

        def _finalize() -> None:
            with closing(_connect()) as conn:
                with conn:
                    conn.execute(
                        """UPDATE reviews SET status='resolved', outcome=?, reviewer_id=?, reason=?,
                               resolved_at=?, precedent_id=?, resolved_decision_json=?
                           WHERE review_id=?""",
                        (outcome, reviewer_id, reason, _now(), precedent_id,
                         resolved.model_dump_json(), review_id),
                    )
                    _insert_audit(conn, envelope, resolved, "resolution")

        try:
            await asyncio.to_thread(_finalize)
        except Exception as e:
            raise AegisError("REVIEW_RESOLVE_FAILED", repr(e)) from e

    await broadcast_live(resolved)
    return resolved


async def replay(decision_hash: str) -> Decision:
    def _work() -> Optional[sqlite3.Row]:
        _ensure_schema_sync()
        with closing(_connect()) as conn:
            return conn.execute(
                "SELECT decision_json, policy_version FROM audit_log WHERE decision_hash=? ORDER BY seq ASC LIMIT 1",
                (decision_hash,),
            ).fetchone()

    row = await asyncio.to_thread(_work)
    if row is None:
        raise AegisError("REPLAY_NOT_FOUND", f"no recorded decision with hash '{decision_hash}'")
    stored = row["decision_json"]
    decision = Decision.model_validate_json(stored)
    if (decision.decision_hash != decision_hash
            or decision.policy_version != row["policy_version"]
            or decision.model_dump_json() != stored):
        raise AegisError("REPLAY_MISMATCH", "stored decision failed byte-for-byte verification")
    return decision


async def shadow_simulate(envelope: ActionEnvelope) -> Decision:
    decision = await _run_pipeline_read_only(envelope)
    await _append_audit(envelope, decision, "shadow")
    return decision


class _LiveHub:
    def __init__(self) -> None:
        self._clients: set = set()

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        self._clients.add(ws)

    def disconnect(self, ws: WebSocket) -> None:
        self._clients.discard(ws)

    async def broadcast(self, text: str) -> None:
        clients = list(self._clients)
        if not clients:
            return

        async def _send(ws):
            try:
                await asyncio.wait_for(ws.send_text(text), timeout=2.0)
                return None
            except Exception:
                return ws

        for dead in await asyncio.gather(*(_send(c) for c in clients)):
            if dead is not None:
                self._clients.discard(dead)


hub = _LiveHub()


async def broadcast_live(decision: Decision) -> None:
    try:
        await hub.broadcast(decision.model_dump_json())
    except Exception:
        pass


router = APIRouter()

_STATUS = {
    "REVIEW_NOT_FOUND": 404, "DECISION_NOT_FOUND": 404, "REPLAY_NOT_FOUND": 404,
    "REVIEW_ALREADY_RESOLVED": 409,
    "INVALID_OUTCOME": 422, "INVALID_INPUT": 422, "REVIEW_NOT_FLAG": 422, "REQUEST_ID_MISMATCH": 422,
}


def _http(e: AegisError) -> HTTPException:
    return HTTPException(status_code=_STATUS.get(e.code, 500), detail={"code": e.code, "message": e.message})


def _dump(d: Decision) -> Dict[str, Any]:
    return d.model_dump(mode="json")


class ResolveReviewRequest(BaseModel):
    outcome: str
    reviewer_id: str
    reason: str


class ReplayRequest(BaseModel):
    decision_hash: str


@router.post("/v1/reviews/{review_id}/resolve")
async def api_resolve_review(review_id: str, body: ResolveReviewRequest):
    try:
        return _dump(await resolve_review(review_id, body.outcome, body.reviewer_id, body.reason))
    except AegisError as e:
        raise _http(e)


@router.post("/v1/replay")
async def api_replay(body: ReplayRequest):
    try:
        return _dump(await replay(body.decision_hash))
    except AegisError as e:
        raise _http(e)


@router.get("/v1/decisions/{request_id}")
async def api_get_decision(request_id: str, include_shadow: bool = Query(False)):
    try:
        return _dump(await get_decision(request_id, include_shadow))
    except AegisError as e:
        raise _http(e)


@router.post("/v1/shadow/simulate")
async def api_shadow_simulate(envelope: ActionEnvelope):
    try:
        return _dump(await shadow_simulate(envelope))
    except AegisError as e:
        raise _http(e)


@router.websocket("/v1/live")
async def ws_live(ws: WebSocket):
    await hub.connect(ws)
    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        hub.disconnect(ws)


def _behavior_sync(agent_id: str, tenant_id: Optional[str], limit: int) -> Dict[str, Any]:
    _ensure_schema_sync()
    where, params = "agent_id=?", [agent_id]
    if tenant_id:
        where += " AND tenant_id=?"
        params.append(tenant_id)
    with closing(_connect()) as conn:
        total, first_seen, last_seen = conn.execute(
            f"SELECT COUNT(*), MIN(logged_at), MAX(logged_at) FROM audit_log WHERE {where} AND mode='live'", params
        ).fetchone()
        rows = conn.execute(
            f"""SELECT request_id, logged_at, tool_name, verdict, risk_score, confidence, latency_ms,
                       estimated_exposure, reason_codes_json
                FROM audit_log WHERE {where} AND mode='live' ORDER BY seq DESC LIMIT ?""",
            params + [limit],
        ).fetchall()
        shadow = conn.execute(
            f"SELECT verdict, COUNT(*) c FROM audit_log WHERE {where} AND mode='shadow' GROUP BY verdict", params
        ).fetchall()
        pending = conn.execute(
            f"SELECT COUNT(*) FROM reviews WHERE {where} AND status='pending'", params
        ).fetchone()[0]
        resolved = conn.execute(
            f"SELECT outcome, COUNT(*) c FROM reviews WHERE {where} AND status='resolved' GROUP BY outcome", params
        ).fetchall()

    n = len(rows)
    verdicts = Counter(r["verdict"] for r in rows)
    tools = Counter(r["tool_name"] for r in rows)
    reasons: Counter = Counter()
    for r in rows:
        reasons.update(json.loads(r["reason_codes_json"]))

    def avg(key: str) -> Optional[float]:
        vals = [r[key] for r in rows if r[key] is not None]
        return round(sum(vals) / len(vals), 4) if vals else None

    return {
        "agent_id": agent_id,
        "total_decisions": total,
        "window_size": n,
        "first_seen": first_seen,
        "last_seen": last_seen,
        "verdict_counts": {v.value: verdicts.get(v.value, 0) for v in Verdict},
        "block_rate": round(verdicts.get("BLOCK", 0) / n, 4) if n else 0.0,
        "flag_rate": round(verdicts.get("FLAG", 0) / n, 4) if n else 0.0,
        "avg_risk_score": avg("risk_score"),
        "max_risk_score": max((r["risk_score"] for r in rows if r["risk_score"] is not None), default=None),
        "avg_confidence": avg("confidence"),
        "avg_latency_ms": avg("latency_ms"),
        "total_estimated_exposure": round(sum(r["estimated_exposure"] or 0.0 for r in rows), 2),
        "top_tools": [{"tool_name": t, "count": c} for t, c in tools.most_common(5)],
        "top_reason_codes": [{"code": t, "count": c} for t, c in reasons.most_common(5)],
        "pending_reviews": pending,
        "human_resolutions": {r["outcome"]: r["c"] for r in resolved},
        "shadow_verdict_counts": {r["verdict"]: r["c"] for r in shadow},
        "recent": [
            {"request_id": r["request_id"], "logged_at": r["logged_at"], "tool_name": r["tool_name"],
             "verdict": r["verdict"], "risk_score": r["risk_score"]}
            for r in rows[:20]
        ],
    }


async def get_agent_behavior(agent_id: str, tenant_id: Optional[str] = None, limit: int = 1000) -> Dict[str, Any]:
    try:
        return await asyncio.to_thread(_behavior_sync, agent_id, tenant_id, limit)
    except AegisError:
        raise
    except Exception as e:
        raise AegisError("BEHAVIOR_QUERY_FAILED", repr(e)) from e


@router.get("/v1/agents/{agent_id}/behavior")
async def api_agent_behavior(agent_id: str, tenant_id: Optional[str] = Query(None),
                             limit: int = Query(1000, ge=1, le=5000)):
    try:
        return await get_agent_behavior(agent_id, tenant_id, limit)
    except AegisError as e:
        raise _http(e)


# =============================================================================
# MOCKS — updated to match the REAL signatures (were previously mocking the
# wrong ones, which would have made standalone AEGIS_PART4_MOCKS=1 tests
# pass while the real integration failed). Only used when injected or
# AEGIS_PART4_MOCKS=1.
# =============================================================================
class MockPart1:
    def __init__(self) -> None:
        self.calls: List[str] = []

    async def run_hard_gate(self, envelope: ActionEnvelope) -> HardGateResult:
        self.calls.append("run_hard_gate")
        return HardGateResult(passed=True, deny=False, reason_codes=[])


class MockPart2:
    def __init__(self) -> None:
        self.calls: List[str] = []
        self.write_calls: List[Dict[str, Any]] = []
        self.revoke_calls: List[Dict[str, Any]] = []

    async def retrieve_evidence(self, envelope: ActionEnvelope) -> EvidenceBundle:
        self.calls.append("retrieve_evidence")
        item = EvidenceItem(id="pol_1", text="Refunds above INR 50,000 need approval", source="policy_doc",
                            freshness_ts=_now(), score=0.91)
        return EvidenceBundle(policy_matches=[item], precedent_matches=[])

    async def write_precedent(self, envelope: ActionEnvelope, outcome: str, reviewer_id: str, reason: str,
                              scope: PrecedentScope) -> PrecedentRecord:
        self.calls.append("write_precedent")
        self.write_calls.append({"envelope": envelope, "scope": scope, "outcome": outcome,
                                 "reviewer_id": reviewer_id, "reason": reason})
        return PrecedentRecord(precedent_id=f"prec_{len(self.write_calls)}", scope=scope, outcome=outcome,
                               reviewer_id=reviewer_id, reason=reason, created_at=_now(), expires_at=None)

    async def revoke_precedent(self, precedent_id: str) -> bool:
        self.calls.append("revoke_precedent")
        self.revoke_calls.append({"precedent_id": precedent_id})
        return True


class MockPart3:
    def __init__(self) -> None:
        self.calls: List[str] = []

    async def compute_risk(self, envelope, evidence) -> RiskAssessment:
        self.calls.append("compute_risk")
        return RiskAssessment(risk_score=0.62, confidence=0.8, reversibility=envelope.reversibility, anomaly_flags=[])

    async def compute_impact(self, envelope, risk) -> ImpactEstimate:
        self.calls.append("compute_impact")
        return ImpactEstimate(estimated_exposure=envelope.estimated_amount, calculation="mock: amount")

    async def decide(self, envelope, evidence, hard_gate, risk, impact) -> Decision:
        self.calls.append("decide")
        verdict = Verdict.FLAG if envelope.operation_class in (
            OperationClass.DELETE, OperationClass.EXPORT, OperationClass.PERMISSION_CHANGE) else Verdict.ALLOW
        h = hashlib.sha256(f"{envelope.request_id}|v1|{verdict.value}".encode()).hexdigest()
        return Decision(
            request_id=envelope.request_id, verdict=verdict, reason_codes=["MOCK"],
            human_explanation="mock decision", policy_ids=["pol_1"], evidence_ids=["pol_1"], precedent_ids=[],
            risk_score=risk.risk_score, confidence=risk.confidence, estimated_exposure=impact.estimated_exposure,
            calculation=impact.calculation, required_approval=verdict == Verdict.FLAG, latency_ms=12.5,
            policy_version="v1", decision_hash=h, expires_at=None, replay_token=f"rt_{h[:12]}",
        )
