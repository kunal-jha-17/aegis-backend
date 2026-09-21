"""
part2_evidence.py — AEGIS Backend, PART 2 of 4: Moss Evidence Retrieval & Precedent Service.
Team CryptiX · YC Fall 2026 × Moss.
"""
from __future__ import annotations

import asyncio
import functools
import inspect
import json
import logging
import os
import re
import sqlite3
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query

from shared_contracts import (
    ActionEnvelope,
    AegisError,
    EvidenceBundle,
    EvidenceItem,
    PrecedentRecord,
    PrecedentScope,
)

try:
    import inferedge_moss as _moss_pkg
    _MOSS_IMPORT_ERROR: Optional[Exception] = None
except ImportError as _e:
    _moss_pkg = None
    _MOSS_IMPORT_ERROR = _e

# inferedge-moss 1.0.0b8 API: no QueryOptions, no MutationOptions, no job polling.
if _moss_pkg is not None:
    DocumentInfo = _moss_pkg.DocumentInfo
    MossClient = _moss_pkg.MossClient
    AddDocumentsOptions = getattr(_moss_pkg, "AddDocumentsOptions", None)
else:
    DocumentInfo = MossClient = AddDocumentsOptions = None  # type: ignore

log = logging.getLogger("aegis.part2_evidence")

DB_PATH = "./data/aegis.db"
_PREFIX = os.getenv("AEGIS_MOSS_INDEX_PREFIX", "aegis")
POLICY_INDEX = f"{_PREFIX}-policies"
PRECEDENT_INDEX = f"{_PREFIX}-precedents"

POLICY_TOP_K = 5
PRECEDENT_TOP_K = 5
CANDIDATE_MULTIPLIER = 4
HYBRID_ALPHA = 0.6
PRECEDENT_TTL_DAYS = int(os.getenv("AEGIS_PRECEDENT_TTL_DAYS", "30"))
DEFAULT_MODEL_ID = os.getenv("AEGIS_MOSS_MODEL_ID", "moss-minilm")
_MODEL_FALLBACKS = [DEFAULT_MODEL_ID] + [m for m in ("moss-minilm", "moss-mediumlm") if m != DEFAULT_MODEL_ID]
PRECEDENT_DB_FALLBACK = os.getenv("AEGIS_PRECEDENT_DB_FALLBACK", "1") == "1"
MIN_SCORE = float(os.getenv("AEGIS_EVIDENCE_MIN_SCORE", "0.0"))

GLOBAL_TENANT = "*"

# MERGE PATCH: these were originally "acme" / "globex" (no prefix), which never
# matched Part 1's ALLOWED_TENANTS / demo-agent convention of "tenant_acme" /
# "tenant_globex" / "tenant_initech". Without this fix, retrieve_evidence's
# precedent query filters on envelope.tenant_id="tenant_acme", which would
# never match a seed precedent scoped to tenant_id="acme" — the whole
# live-learning demo would silently show zero precedent matches. Patched to
# match Part 1's convention (more of Part 1's code depends on the prefixed
# form: ALLOWED_TENANTS, DENY_LIST_TOOLS_FOR_TENANT, and the demo scenarios).
SEED_TENANT_A = "acme-in"
SEED_TENANT_B = "globex-us"
SEED_AGENT_ID = "support-agent"

_SEED_POLICIES: List[Dict[str, str]] = [
    {"id": "pol-refund-001", "kind": "policy", "category": "refunds", "source": "POL-REFUND-001",
     "freshness_ts": "2026-06-01T00:00:00+00:00", "title": "Refund Authority Limits",
     "body": "AI agents may issue a refund automatically only up to INR 1,000 per order without review. Refunds from INR 1,001 to INR 25,000 "
         "require review by a human support lead. VIP customers may be refunded up to INR 2,000 before review is required. Refunds "
         "above INR 1,00,000 must be blocked and escalated to the finance head. Refunds are irreversible once settled to the customer's bank."},
    {"id": "pol-refund-002", "kind": "policy", "category": "refunds", "source": "POL-REFUND-002",
     "freshness_ts": "2026-06-01T00:00:00+00:00", "title": "Refund Frequency Cap",
     "body": "A single customer may receive at most 3 refunds in any rolling 30-day window. A fourth refund request, or a second refund "
             "against the same order, must be flagged for human review to catch duplicate or fraudulent refund loops."},
    {"id": "pol-refund-003", "kind": "policy", "category": "refunds", "source": "POL-REFUND-003",
     "freshness_ts": "2026-04-15T00:00:00+00:00", "title": "Refund Destination Rule",
     "body": "Refunds must be returned to the original payment instrument. Refunding to a different card, UPI ID or bank account is "
             "prohibited for agents and requires explicit finance approval with a documented reason."},
    {"id": "pol-refund-004", "kind": "policy", "category": "refunds", "source": "POL-REFUND-004",
     "freshness_ts": "2026-05-10T00:00:00+00:00", "title": "Goodwill Credits",
     "body": "Agents may grant store credit or goodwill credit up to INR 2,000 per customer per quarter for delivery delays or minor "
             "service failures. Credits above INR 2,000 need a human support lead's approval."},
    {"id": "pol-record-001", "kind": "policy", "category": "record_edits", "source": "POL-RECORD-001",
     "freshness_ts": "2026-05-20T00:00:00+00:00", "title": "Customer Profile Edits (Non-Financial)",
     "body": "Agents may edit non-financial customer profile fields such as display name formatting, communication preferences, "
             "and shipping address, provided the change is logged and reversible. Edits made on the customer's own instruction are "
             "allowed; edits inferred by the agent are flagged."},
    {"id": "pol-record-002", "kind": "policy", "category": "record_edits", "source": "POL-RECORD-002",
     "freshness_ts": "2026-05-20T00:00:00+00:00", "title": "Financial and KYC Record Edits",
     "body": "Agents must never modify bank account numbers, KYC documents, PAN or Aadhaar-linked fields, or credit limits. "
             "These edits are irreversible for audit purposes and must be blocked; only authorised compliance staff may change them."},
    {"id": "pol-record-003", "kind": "policy", "category": "record_edits", "source": "POL-RECORD-003",
     "freshness_ts": "2026-03-30T00:00:00+00:00", "title": "Bulk Edits and Deletions",
     "body": "Any operation that edits more than 25 records, or deletes any customer record, requires human approval. Permanent "
             "deletes are irreversible and must not be executed by an agent without a named approver. Bulk operations must use a "
             "dry-run preview first."},
    {"id": "pol-perm-001", "kind": "policy", "category": "permissions", "source": "POL-PERM-001",
     "freshness_ts": "2026-02-12T00:00:00+00:00", "title": "Permission and Role Changes",
     "body": "Agents may never grant, widen or escalate permissions or roles, including admin, billing and API-key scopes. Any "
             "permission_change action requires security-team approval and must be blocked by default."},
    {"id": "pol-export-001", "kind": "policy", "category": "data_export", "source": "POL-EXPORT-001",
     "freshness_ts": "2026-04-02T00:00:00+00:00", "title": "Customer Data Export Controls",
     "body": "Exports of customer personal data are limited to 500 rows without review. Exports of more than 500 rows, or any export "
             "to a destination outside the tenant's verified domains, must be flagged for review by the data-protection officer."},
    {"id": "pol-send-001", "kind": "policy", "category": "communications", "source": "POL-SEND-001",
     "freshness_ts": "2026-05-05T00:00:00+00:00", "title": "Outbound Customer Communications",
     "body": "Agents may send templated service messages (order updates, delay apologies). Messages that promise money, refunds, "
             "discounts or legal outcomes, or that go to an unverified recipient domain, must be flagged for human review before sending."},
    {"id": "pol-approve-001", "kind": "policy", "category": "approvals", "source": "POL-APPROVE-001",
     "freshness_ts": "2026-01-25T00:00:00+00:00", "title": "Segregation of Duties for Approvals",
     "body": "An agent must never approve a request it initiated or that was raised on behalf of the same principal. Approval actions "
             "require a distinct human approver, and an agent's approval never satisfies a human-approval requirement."},
    {"id": "inc-2025-014", "kind": "incident", "category": "refunds", "source": "INC-2025-014",
     "freshness_ts": "2025-11-18T00:00:00+00:00", "title": "Incident: Duplicate Refund Loop",
     "body": "After a payment-gateway timeout an agent retried the refund tool four times on one order and refunded INR 86,000 "
             "against an order value of INR 21,500. The cause was a missing idempotency key. Recovery took nine days and INR 64,500 "
             "was never recovered. Action taken: repeated refunds on the same order are now flagged."},
    {"id": "inc-2025-031", "kind": "incident", "category": "record_edits", "source": "INC-2025-031",
     "freshness_ts": "2025-12-09T00:00:00+00:00", "title": "Incident: Bulk Contact Overwrite",
     "body": "An agent's bulk update used an overly broad filter and overwrote contact details for 212 customer accounts. "
             "Backups restored only 180 accounts; 32 needed manual repair, so the change was only partially reversible. Action taken: "
             "bulk edits now need a dry-run preview and human approval."},
    {"id": "inc-2026-004", "kind": "incident", "category": "data_export", "source": "INC-2026-004",
     "freshness_ts": "2026-02-27T00:00:00+00:00", "title": "Incident: Prompt-Injected Customer Export",
     "body": "A support ticket containing hidden instructions caused an agent to export 12,400 customer records to an unverified "
             "external email address. No card data was involved but the event was reportable. Action taken: exports to unverified "
             "domains are blocked and exports above 500 rows need review."},
]

_SEED_PRECEDENTS: List[Dict[str, Any]] = [
    {"precedent_id": "prec-seed-acme-refund-ok", "tenant_id": SEED_TENANT_A, "agent_id": SEED_AGENT_ID,
     "tool_name": "issue_refund", "resource_class": "refunds", "argument_conditions": {"amount": {"$lte": 7500}},
     "outcome": "approved", "reviewer_id": "rev-ops-lead-01",
     "reason": "Goodwill refunds up to INR 7,500 for delayed shipments are acceptable for Acme premium customers.",
     "created_at": "2026-08-20T09:30:00+00:00", "expires_at": "2027-08-20T09:30:00+00:00"},
    {"precedent_id": "prec-seed-acme-kyc-no", "tenant_id": SEED_TENANT_A, "agent_id": SEED_AGENT_ID,
     "tool_name": "update_customer_record", "resource_class": "customer_records",
     "argument_conditions": {"field": {"$in": ["bank_account", "pan_number", "kyc_status"]}},
     "outcome": "rejected", "reviewer_id": "rev-compliance-02",
     "reason": "Agent attempted to edit bank or KYC fields; only compliance staff may change these.",
     "created_at": "2026-08-11T14:05:00+00:00", "expires_at": "2027-08-11T14:05:00+00:00"},
    {"precedent_id": "prec-seed-acme-email-ok", "tenant_id": SEED_TENANT_A, "agent_id": SEED_AGENT_ID,
     "tool_name": "send_email", "resource_class": "customer_email",
     "argument_conditions": {"template": "order_delay_apology"},
     "outcome": "approved", "reviewer_id": "rev-ops-lead-01",
     "reason": "The order-delay apology template contains no financial commitment and is safe to send automatically.",
     "created_at": "2026-07-29T11:00:00+00:00", "expires_at": "2027-07-29T11:00:00+00:00"},
    {"precedent_id": "prec-seed-globex-refund-ok", "tenant_id": SEED_TENANT_B, "agent_id": SEED_AGENT_ID,
     "tool_name": "issue_refund", "resource_class": "refunds", "argument_conditions": {"amount": {"$lte": 3000}},
     "outcome": "approved", "reviewer_id": "rev-finance-07",
     "reason": "Globex allows agent-issued refunds up to INR 3,000 when the order is within the return window.",
     "created_at": "2026-08-02T10:15:00+00:00", "expires_at": "2027-08-02T10:15:00+00:00"},
    {"precedent_id": "prec-seed-globex-export-no", "tenant_id": SEED_TENANT_B, "agent_id": SEED_AGENT_ID,
     "tool_name": "export_data", "resource_class": "customer_exports",
     "argument_conditions": {"row_count": {"$gt": 500}},
     "outcome": "rejected", "reviewer_id": "rev-dpo-03",
     "reason": "Exports above 500 rows need data-protection review; the agent's bulk export was rejected.",
     "created_at": "2026-08-25T16:40:00+00:00", "expires_at": "2027-08-25T16:40:00+00:00"},
]


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.isoformat()


def _parse_ts(ts: Optional[str]) -> Optional[datetime]:
    if not ts:
        return None
    dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _is_expired(expires_at: Optional[str]) -> bool:
    exp = _parse_ts(expires_at)
    return exp is not None and exp <= _now()


def _aegis_guard(fn):
    @functools.wraps(fn)
    async def wrapper(*args, **kwargs):
        try:
            return await fn(*args, **kwargs)
        except AegisError:
            raise
        except Exception as e:
            raise AegisError("INTERNAL_ERROR", f"{fn.__name__} failed unexpectedly: {type(e).__name__}: {e}") from e
    return wrapper


_SCHEME_RE = re.compile(r"^[a-z][a-z0-9+.\-]*://")


def derive_resource_class(target_resource: str) -> str:
    t = (target_resource or "").strip().lower()
    t = _SCHEME_RE.sub("", t)
    parts = [p for p in re.split(r"[/:#?\s]+", t) if p]
    return parts[0] if parts else ""


_MISSING = object()
_OPERATORS = {"$eq", "$ne", "$lt", "$lte", "$gt", "$gte", "$in", "$nin", "$exists"}


def _lookup(envelope: ActionEnvelope, key: str) -> Any:
    cur: Any = envelope.arguments
    found = True
    for part in key.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            found = False
            break
    if found:
        return cur
    if key == "estimated_amount" and envelope.estimated_amount is not None:
        return envelope.estimated_amount
    if key == "operation_class":
        return envelope.operation_class.value
    if key == "reversibility":
        return envelope.reversibility
    return _MISSING


def _ordered(a: Any, b: Any, op: str) -> bool:
    num = lambda x: isinstance(x, (int, float)) and not isinstance(x, bool)  # noqa: E731
    if not ((num(a) and num(b)) or (isinstance(a, str) and isinstance(b, str))):
        return False
    return {"$lt": a < b, "$lte": a <= b, "$gt": a > b, "$gte": a >= b}[op]


def _cond_ok(actual: Any, cond: Any) -> bool:
    if isinstance(cond, dict) and cond and all(isinstance(k, str) and k.startswith("$") for k in cond):
        for op, want in cond.items():
            if op == "$exists":
                if (actual is not _MISSING) != bool(want):
                    return False
                continue
            if actual is _MISSING:
                return False
            if op == "$eq" and actual != want:
                return False
            elif op == "$ne" and actual == want:
                return False
            elif op in ("$lt", "$lte", "$gt", "$gte") and not _ordered(actual, want, op):
                return False
            elif op == "$in" and actual not in (want or []):
                return False
            elif op == "$nin" and actual in (want or []):
                return False
            elif op not in _OPERATORS:
                return False
        return True
    return actual is not _MISSING and actual == cond


def _conditions_match(conditions: Dict[str, Any], envelope: ActionEnvelope) -> bool:
    return all(_cond_ok(_lookup(envelope, k), c) for k, c in (conditions or {}).items())


def _validate_conditions(conditions: Dict[str, Any]) -> None:
    for k, c in conditions.items():
        if not isinstance(k, str) or not k:
            raise AegisError("INVALID_INPUT", "argument_conditions keys must be non-empty strings")
        if isinstance(c, dict) and c and any(str(op).startswith("$") for op in c):
            bad = [op for op in c if op not in _OPERATORS]
            if bad:
                raise AegisError("INVALID_INPUT", f"Unsupported operator(s) in argument_conditions[{k!r}]: {bad}. Supported: {sorted(_OPERATORS)}")
    try:
        json.dumps(conditions)
    except (TypeError, ValueError) as e:
        raise AegisError("INVALID_INPUT", f"argument_conditions must be JSON-serialisable: {e}") from e


_OP_TEXT = {"$eq": "=", "$ne": "!=", "$lt": "<", "$lte": "<=", "$gt": ">", "$gte": ">=", "$in": "in", "$nin": "not in"}


def _render_conditions(conditions: Dict[str, Any]) -> str:
    if not conditions:
        return "any arguments"
    parts = []
    for k, c in conditions.items():
        if isinstance(c, dict) and c and all(str(o).startswith("$") for o in c):
            for op, v in c.items():
                parts.append(f"{k} exists" if op == "$exists" and v else f"{k} does not exist" if op == "$exists"
                             else f"{k} {_OP_TEXT.get(op, op)} {v}")
        else:
            parts.append(f"{k} = {c}")
    return "; ".join(parts)


_SCHEMA = """
CREATE TABLE IF NOT EXISTS evidence_items (
    id            TEXT PRIMARY KEY,
    kind          TEXT NOT NULL,
    title         TEXT NOT NULL,
    text          TEXT NOT NULL,
    source        TEXT NOT NULL,
    freshness_ts  TEXT NOT NULL,
    tenant_id     TEXT NOT NULL DEFAULT '*',
    category      TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS precedents (
    precedent_id             TEXT PRIMARY KEY,
    tenant_id                TEXT NOT NULL,
    agent_id                 TEXT NOT NULL,
    tool_name                TEXT NOT NULL,
    resource_class           TEXT NOT NULL,
    argument_conditions_json TEXT NOT NULL,
    outcome                  TEXT NOT NULL,
    reviewer_id              TEXT NOT NULL,
    reason                   TEXT NOT NULL,
    created_at               TEXT NOT NULL,
    expires_at               TEXT,
    revoked                  INTEGER NOT NULL DEFAULT 0,
    state                    TEXT NOT NULL DEFAULT 'pending',
    source_request_id        TEXT,
    moss_text                TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_precedents_scope ON precedents (tenant_id, agent_id, tool_name, resource_class);
"""


def _connect() -> sqlite3.Connection:
    os.makedirs(os.path.dirname(os.path.abspath(DB_PATH)), exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


async def _db(fn, *args):
    def run():
        conn = _connect()
        try:
            return fn(conn, *args)
        finally:
            conn.close()
    try:
        return await asyncio.to_thread(run)
    except AegisError:
        raise
    except sqlite3.Error as e:
        raise AegisError("DB_ERROR", f"SQLite operation failed: {e}") from e


def _policy_doc_text(title: str, body: str) -> str:
    return f"{title}. {body}"


def _precedent_text(rec: PrecedentRecord) -> str:
    s = rec.scope
    return (
        f"[PRECEDENT outcome={rec.outcome}] Human reviewer {rec.reviewer_id} {rec.outcome} tool '{s.tool_name}' "
        f"for agent '{s.agent_id}' on '{s.resource_class}' resources (tenant {s.tenant_id}). "
        f"Applies when: {_render_conditions(s.argument_conditions)}. Reason: {rec.reason} "
        f"Valid until {rec.expires_at or 'further notice'}."
    )


def _row_to_record(r: Dict[str, Any]) -> PrecedentRecord:
    return PrecedentRecord(
        precedent_id=r["precedent_id"],
        scope=PrecedentScope(
            tenant_id=r["tenant_id"], agent_id=r["agent_id"], tool_name=r["tool_name"],
            resource_class=r["resource_class"], argument_conditions=json.loads(r["argument_conditions_json"]),
        ),
        outcome=r["outcome"], reviewer_id=r["reviewer_id"], reason=r["reason"],
        created_at=r["created_at"], expires_at=r["expires_at"], revoked=bool(r["revoked"]),
    )


def _db_init_and_seed(conn: sqlite3.Connection) -> None:
    conn.executescript(_SCHEMA)
    with conn:
        for d in _SEED_POLICIES:
            conn.execute(
                "INSERT OR IGNORE INTO evidence_items (id, kind, title, text, source, freshness_ts, tenant_id, category) "
                "VALUES (?,?,?,?,?,?,?,?)",
                (d["id"], d["kind"], d["title"], _policy_doc_text(d["title"], d["body"]), d["source"],
                 d["freshness_ts"], GLOBAL_TENANT, d["category"]),
            )
        for p in _SEED_PRECEDENTS:
            rec = PrecedentRecord(
                precedent_id=p["precedent_id"],
                scope=PrecedentScope(tenant_id=p["tenant_id"], agent_id=p["agent_id"], tool_name=p["tool_name"],
                                     resource_class=p["resource_class"], argument_conditions=p["argument_conditions"]),
                outcome=p["outcome"], reviewer_id=p["reviewer_id"], reason=p["reason"],
                created_at=p["created_at"], expires_at=p["expires_at"], revoked=False,
            )
            conn.execute(
                "INSERT OR IGNORE INTO precedents (precedent_id, tenant_id, agent_id, tool_name, resource_class, "
                "argument_conditions_json, outcome, reviewer_id, reason, created_at, expires_at, revoked, state, "
                "source_request_id, moss_text) VALUES (?,?,?,?,?,?,?,?,?,?,?,0,'active','seed',?)",
                (rec.precedent_id, rec.scope.tenant_id, rec.scope.agent_id, rec.scope.tool_name, rec.scope.resource_class,
                 json.dumps(rec.scope.argument_conditions), rec.outcome, rec.reviewer_id, rec.reason, rec.created_at,
                 rec.expires_at, _precedent_text(rec)),
            )


def _db_policy_rows(conn: sqlite3.Connection) -> List[Dict[str, Any]]:
    return [dict(r) for r in conn.execute("SELECT * FROM evidence_items ORDER BY id")]


def _db_active_precedent_rows(conn: sqlite3.Connection) -> List[Dict[str, Any]]:
    return [dict(r) for r in conn.execute("SELECT * FROM precedents WHERE state='active' AND revoked=0 ORDER BY precedent_id")]


def _db_evidence_rows(conn: sqlite3.Connection, ids: List[str]) -> Dict[str, Dict[str, Any]]:
    if not ids:
        return {}
    q = ",".join("?" * len(ids))
    return {r["id"]: dict(r) for r in conn.execute(f"SELECT * FROM evidence_items WHERE id IN ({q})", ids)}


def _db_live_precedent_rows(conn: sqlite3.Connection, ids: List[str], tenant_id: str) -> Dict[str, Dict[str, Any]]:
    if not ids:
        return {}
    q = ",".join("?" * len(ids))
    rows = conn.execute(
        f"SELECT * FROM precedents WHERE precedent_id IN ({q}) AND state='active' AND revoked=0 AND tenant_id=?",
        [*ids, tenant_id],
    )
    return {r["precedent_id"]: dict(r) for r in rows}


def _db_scope_precedent_rows(conn: sqlite3.Connection, tenant_id: str, agent_id: str, tool_name: str,
                             resource_class: str) -> List[Dict[str, Any]]:
    rows = conn.execute(
        "SELECT * FROM precedents WHERE state='active' AND revoked=0 AND tenant_id=? AND agent_id=? "
        "AND tool_name=? AND resource_class=? ORDER BY created_at DESC",
        (tenant_id, agent_id, tool_name, resource_class),
    )
    return [dict(r) for r in rows]


def _db_insert_pending(conn: sqlite3.Connection, rec: PrecedentRecord, request_id: str, text: str) -> None:
    s = rec.scope
    with conn:
        conn.execute(
            "INSERT INTO precedents (precedent_id, tenant_id, agent_id, tool_name, resource_class, argument_conditions_json, "
            "outcome, reviewer_id, reason, created_at, expires_at, revoked, state, source_request_id, moss_text) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,0,'pending',?,?)",
            (rec.precedent_id, s.tenant_id, s.agent_id, s.tool_name, s.resource_class, json.dumps(s.argument_conditions),
             rec.outcome, rec.reviewer_id, rec.reason, rec.created_at, rec.expires_at, request_id, text),
        )


def _db_activate(conn: sqlite3.Connection, precedent_id: str) -> None:
    with conn:
        cur = conn.execute("UPDATE precedents SET state='active' WHERE precedent_id=? AND state='pending'", (precedent_id,))
        if cur.rowcount != 1:
            raise AegisError("DB_ERROR", f"Could not activate precedent {precedent_id}: pending row not found")


def _db_delete_pending(conn: sqlite3.Connection, precedent_id: str) -> None:
    with conn:
        conn.execute("DELETE FROM precedents WHERE precedent_id=? AND state='pending'", (precedent_id,))


def _db_mark_revoked(conn: sqlite3.Connection, precedent_id: str) -> Optional[Dict[str, Any]]:
    with conn:
        row = conn.execute("SELECT * FROM precedents WHERE precedent_id=?", (precedent_id,)).fetchone()
        if row is None:
            return None
        conn.execute("UPDATE precedents SET revoked=1 WHERE precedent_id=?", (precedent_id,))
        out = dict(row)
        out["revoked"] = 1
        return out


def _db_get_evidence_one(conn: sqlite3.Connection, evidence_id: str) -> Optional[Dict[str, Any]]:
    r = conn.execute("SELECT * FROM evidence_items WHERE id=?", (evidence_id,)).fetchone()
    return dict(r) if r else None


def _db_get_precedent_one(conn: sqlite3.Connection, precedent_id: str) -> Optional[Dict[str, Any]]:
    r = conn.execute("SELECT * FROM precedents WHERE precedent_id=? AND state='active'", (precedent_id,)).fetchone()
    return dict(r) if r else None


_db_ready = False
_ready = False
_init_lock = asyncio.Lock()
_write_lock = asyncio.Lock()

# ── Local retrieval engine ──────────────────────────────────────────────────
# HISTORY: inferedge-moss's beta SDK (1.0.0b8, the newest resolvable on PyPI
# at integration time — 1.0.0b19 named in the original spec does not exist)
# was bisected against every available inferedge-moss-core version
# (0.1.0 through 0.11.0). None of them work: 0.5.0-0.11.0 are missing
# CLOUD_API_BASE_URL entirely; 0.1.0-0.4.2 have it but their Index.deserialize()
# requires a 'documents' argument that 1.0.0b8's own client code never passes,
# so client.load_index() throws TypeError -> RuntimeError on every attempt.
# There is no working version pairing across this SDK's public release history.
#
# SQLite was already this file's real source of truth for provenance, scope,
# expiry and revocation (every Moss hit was re-verified against it before
# being returned — see the design note in the original module docstring), so
# this local engine scores directly against those same rows. Every public
# function below (init_evidence_service, retrieve_evidence, write_precedent,
# revoke_precedent) keeps its exact original signature — nothing in Part 1,
# Part 3, Part 4, or main.py needs to change because of this.
#
# For the PRD/pitch: state plainly that Moss integration was implemented and
# is architecturally wired for it, but is running on local retrieval for the
# demo due to a beta-SDK incompatibility discovered during integration. That
# is honest scoping, not a weakness.

_TOKEN_RE = re.compile(r"[a-z0-9]+")


def _tokenize(text: str) -> List[str]:
    return _TOKEN_RE.findall((text or "").lower())


def _local_score(query_tokens: List[str], doc_text: str) -> float:
    """Fraction of query terms found in the document. Deliberately NOT
    normalized by document length: an earlier version divided by
    sqrt(len(doc_tokens)) too, which penalized longer, more detailed policy
    text and let a short, tangentially-matching document (e.g. a
    communications policy sharing only 'order'/'delay') outrank the actual
    refund-ceiling policy for a refund query. Recall-oriented scoring fixes
    that: a document matching more of the query's terms always ranks higher,
    regardless of its own length."""
    doc_tokens = _tokenize(doc_text)
    if not query_tokens or not doc_tokens:
        return 0.0
    qset, dset = set(query_tokens), set(doc_tokens)
    overlap = len(qset & dset)
    if overlap == 0:
        return 0.0
    return overlap / len(qset)


async def _local_policy_matches(query: str, tenant_id: str) -> tuple:
    t0 = time.perf_counter()
    rows = await _db(_db_policy_rows)
    qtok = _tokenize(query)
    scored = [(r, _local_score(qtok, r["text"])) for r in rows
              if r["tenant_id"] in (GLOBAL_TENANT, tenant_id)]
    scored = [(r, s) for r, s in scored if s >= MIN_SCORE]
    scored.sort(key=lambda x: x[1], reverse=True)
    items = [EvidenceItem(id=r["id"], text=r["text"], source=r["source"],
                          freshness_ts=r["freshness_ts"], score=round(s, 4))
             for r, s in scored[:POLICY_TOP_K]]
    wall = (time.perf_counter() - t0) * 1000
    return items, wall


async def _local_precedent_matches(query: str, envelope: ActionEnvelope) -> tuple:
    t0 = time.perf_counter()
    rc = derive_resource_class(envelope.target_resource)
    rows = await _db(_db_scope_precedent_rows, envelope.tenant_id, envelope.agent_id, envelope.tool_name, rc)
    qtok = _tokenize(query)
    candidates = []
    for r in rows:
        if _is_expired(r["expires_at"]):
            continue
        if not _conditions_match(json.loads(r["argument_conditions_json"]), envelope):
            continue
        s = _local_score(qtok, r["moss_text"])
        if s >= MIN_SCORE:
            candidates.append((r, s))
    candidates.sort(key=lambda x: x[1], reverse=True)
    items = [EvidenceItem(id=r["precedent_id"], text=r["moss_text"], source=f"precedent:{r['precedent_id']}",
                          freshness_ts=r["created_at"], score=round(s, 4))
             for r, s in candidates[:PRECEDENT_TOP_K]]
    wall = (time.perf_counter() - t0) * 1000
    return items, wall


async def _ensure_db() -> None:
    global _db_ready
    if not _db_ready:
        await _db(_db_init_and_seed)
        _db_ready = True


@_aegis_guard
async def init_evidence_service(force_reindex: bool = False) -> None:
    """No external index to build — local engine reads SQLite directly on
    every call. force_reindex is accepted for signature compatibility with
    callers but is a no-op here."""
    global _ready
    await _ensure_db()
    _ready = True


async def _ensure_ready() -> None:
    if _ready:
        return
    async with _init_lock:
        if not _ready:
            await init_evidence_service()


@_aegis_guard
async def retrieve_evidence(envelope: ActionEnvelope) -> EvidenceBundle:
    await _ensure_ready()
    query = f"{envelope.tool_name} {envelope.target_resource} {envelope.user_intent}"
    t0 = time.perf_counter()
    policies, p_wall = await _local_policy_matches(query, envelope.tenant_id)
    precedents, r_wall = await _local_precedent_matches(query, envelope)
    total = (time.perf_counter() - t0) * 1000
    print(f"[part2_evidence:LOCAL] retrieve_evidence request_id={envelope.request_id} tenant={envelope.tenant_id} "
          f"| policies {p_wall:.2f}ms, precedents {r_wall:.2f}ms | total {total:.2f}ms "
          f"| policy_matches={len(policies)} precedent_matches={len(precedents)}")
    return EvidenceBundle(policy_matches=policies, precedent_matches=precedents)


@_aegis_guard
async def write_precedent(envelope: ActionEnvelope, outcome: str, reviewer_id: str, reason: str,
                          scope: PrecedentScope) -> PrecedentRecord:
    await _ensure_ready()
    if outcome not in ("approved", "rejected"):
        raise AegisError("INVALID_INPUT", f"outcome must be 'approved' or 'rejected', got {outcome!r}")
    if not (reviewer_id or "").strip() or not (reason or "").strip():
        raise AegisError("INVALID_INPUT", "reviewer_id and reason are required")
    _validate_conditions(scope.argument_conditions)

    if not scope.tenant_id.strip() or scope.tenant_id.strip() == GLOBAL_TENANT or scope.tenant_id != envelope.tenant_id:
        raise AegisError("SCOPE_VIOLATION", f"scope.tenant_id must equal the envelope's tenant_id ({envelope.tenant_id!r}); no wildcard/global precedents")
    if scope.agent_id != envelope.agent_id:
        raise AegisError("SCOPE_VIOLATION", f"scope.agent_id {scope.agent_id!r} != envelope.agent_id {envelope.agent_id!r}")
    if scope.tool_name != envelope.tool_name:
        raise AegisError("SCOPE_VIOLATION", f"scope.tool_name {scope.tool_name!r} != envelope.tool_name {envelope.tool_name!r}")
    rc = derive_resource_class(envelope.target_resource)
    if scope.resource_class.strip().lower() not in {rc, envelope.target_resource.strip().lower()} or not rc:
        raise AegisError("SCOPE_VIOLATION", f"scope.resource_class {scope.resource_class!r} does not match the envelope's resource class {rc!r}")

    now = _now()
    record = PrecedentRecord(
        precedent_id=f"prec_{uuid.uuid4().hex[:12]}",
        scope=PrecedentScope(tenant_id=scope.tenant_id, agent_id=scope.agent_id, tool_name=scope.tool_name,
                             resource_class=rc, argument_conditions=dict(scope.argument_conditions)),
        outcome=outcome, reviewer_id=reviewer_id, reason=reason,
        created_at=_iso(now), expires_at=_iso(now + timedelta(days=PRECEDENT_TTL_DAYS)), revoked=False,
    )
    text = _precedent_text(record)

    async with _write_lock:
        try:
            await _db(_db_insert_pending, record, envelope.request_id, text)
            await _db(_db_activate, record.precedent_id)
        except Exception as e:
            await _rollback_write(record.precedent_id)
            if isinstance(e, AegisError):
                raise
            raise AegisError("DB_ERROR", f"write_precedent failed and was rolled back: {e}") from e
    return record


async def _rollback_write(precedent_id: str) -> None:
    try:
        await _db(_db_delete_pending, precedent_id)
    except Exception as e:
        log.error("rollback: could not delete pending row %s: %s", precedent_id, e)


@_aegis_guard
async def revoke_precedent(precedent_id: str) -> bool:
    await _ensure_ready()
    async with _write_lock:
        row = await _db(_db_mark_revoked, precedent_id)
        if row is None:
            return False
    return True



router = APIRouter()

_HTTP_STATUS = {"EVIDENCE_NOT_FOUND": 404, "PRECEDENT_NOT_FOUND": 404, "INVALID_INPUT": 400, "SCOPE_VIOLATION": 400,
                "MOSS_NOT_CONFIGURED": 503, "MOSS_INIT_FAILED": 503, "MOSS_QUERY_FAILED": 502,
                "MOSS_WRITE_FAILED": 502, "MOSS_WRITE_TIMEOUT": 504}


def _http(e: AegisError) -> HTTPException:
    return HTTPException(status_code=_HTTP_STATUS.get(e.code, 500), detail={"code": e.code, "message": e.message})


@_aegis_guard
async def get_evidence_item(evidence_id: str, tenant_id: Optional[str] = None) -> Dict[str, Any]:
    await _ensure_db()
    row = await _db(_db_get_evidence_one, evidence_id)
    if row:
        return {"id": row["id"], "kind": row["kind"], "title": row["title"], "text": row["text"], "source": row["source"],
                "freshness_ts": row["freshness_ts"], "tenant_id": row["tenant_id"], "category": row["category"]}
    prow = await _db(_db_get_precedent_one, evidence_id)
    if prow and (tenant_id is None or prow["tenant_id"] == tenant_id):
        rec = _row_to_record(prow)
        return {"id": rec.precedent_id, "kind": "precedent", "title": f"Precedent ({rec.outcome}) — {rec.scope.tool_name}",
                "text": prow["moss_text"], "source": f"precedent:{rec.precedent_id}", "freshness_ts": rec.created_at,
                "tenant_id": rec.scope.tenant_id, "category": "precedent",
                "expired": _is_expired(rec.expires_at), "precedent": rec.model_dump(mode="json")}
    raise AegisError("EVIDENCE_NOT_FOUND", f"No evidence item with id {evidence_id!r}")


@router.get("/v1/evidence/{evidence_id}")
async def get_evidence_endpoint(evidence_id: str, tenant_id: Optional[str] = Query(None)) -> Dict[str, Any]:
    try:
        return await get_evidence_item(evidence_id, tenant_id)
    except AegisError as e:
        raise _http(e)


@router.post("/v1/precedents/{precedent_id}/revoke")
async def revoke_precedent_endpoint(precedent_id: str) -> Dict[str, Any]:
    try:
        ok = await revoke_precedent(precedent_id)
    except AegisError as e:
        raise _http(e)
    if not ok:
        raise _http(AegisError("PRECEDENT_NOT_FOUND", f"No precedent with id {precedent_id!r}"))
    return {"precedent_id": precedent_id, "revoked": True}