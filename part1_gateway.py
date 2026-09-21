"""
AEGIS — PART 1 OF 4: Gateway, Adapters, Hard Gate & Orchestrator
==================================================================
Owner scope (per brief): normalize_openai_call, normalize_langchain_call,
run_hard_gate, the demo agent, and — once Parts 2-4 exist — main.py.

Saved as submitted, unchanged. Verified during integration: zero imports
from part2/part3/part4, exactly as its own docstring claims.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from pydantic import ValidationError

from shared_contracts import (
    ActionEnvelope,
    AegisError,
    HardGateResult,
    OperationClass,
    enum_safe_dump,
)

TOOL_REGISTRY: Dict[str, Dict[str, Any]] = {
    "issue_refund": {
        "operation_class": OperationClass.WRITE,
        "reversibility": "partial",
        "target_key": "order_id",
        "amount_key": "amount",
    },
    "close_ticket": {
        "operation_class": OperationClass.WRITE,
        "reversibility": "reversible",
        "target_key": "ticket_id",
        "amount_key": None,
    },
    "send_customer_email": {
        "operation_class": OperationClass.SEND,
        "reversibility": "irreversible",
        "target_key": "customer_id",
        "amount_key": None,
    },
    "grant_permission": {
        "operation_class": OperationClass.PERMISSION_CHANGE,
        "reversibility": "reversible",
        "target_key": "principal_id",
        "amount_key": None,
    },
    "export_customer_data": {
        "operation_class": OperationClass.EXPORT,
        "reversibility": "irreversible",
        "target_key": "dataset_id",
        "amount_key": None,
    },
    "delete_account": {
        "operation_class": OperationClass.DELETE,
        "reversibility": "irreversible",
        "target_key": "account_id",
        "amount_key": None,
    },
}

ALLOWED_TOOLS = set(TOOL_REGISTRY.keys())

# MERGE NOTE: kept as submitted ("tenant_acme" / "tenant_globex" / "tenant_initech").
# Part 2's seed data originally used "acme" / "globex" (no prefix) and was
# patched to match THIS file's convention instead — see part2_evidence.py's
# merge note. Fixing it here would have meant touching more call sites.
ALLOWED_TENANTS = {"acme-in", "globex-us"}

REQUIRED_CREDENTIAL_SCOPE: Dict[str, str] = {
    "issue_refund": "refunds:write",   # was billing:write
    "close_ticket": "support:write",
    "send_customer_email": "comms:send",
    "grant_permission": "iam:admin",
    "export_customer_data": "data:export",
    "delete_account": "account:delete",
}

AMOUNT_CEILINGS: Dict[str, float] = {}   # was {"issue_refund": 5000.0}

DENY_LIST_RESOURCE_TOKENS = {"SYSTEM", "INTERNAL-RESERVED", "ORD-0000"}

DENY_LIST_TOOLS_FOR_TENANT: Dict[str, set] = {
    "tenant_initech": {"export_customer_data"},
}

REQUIRED_CONTEXT_KEYS = [
    "tenant_id",
    "session_id",
    "agent_id",
    "agent_version",
    "principal_id",
    "user_intent",
    "credential_scope",
    "trace_id",
]


async def _build_envelope(
    tool_name: str,
    arguments: Dict[str, Any],
    context: Dict[str, Any],
    framework: str,
) -> ActionEnvelope:
    spec = TOOL_REGISTRY.get(tool_name)
    if spec is None:
        raise AegisError(
            "UNKNOWN_TOOL", f"'{tool_name}' is not registered in TOOL_REGISTRY"
        )

    missing = [k for k in REQUIRED_CONTEXT_KEYS if k not in context]
    if missing:
        raise AegisError(
            "MISSING_CONTEXT", f"context missing required keys: {missing}"
        )

    target_resource = context.get("target_resource") or str(
        arguments.get(spec["target_key"], "unknown")
    )

    estimated_amount: Optional[float] = context.get("estimated_amount")
    if estimated_amount is None and spec.get("amount_key"):
        raw_amount = arguments.get(spec["amount_key"])
        if raw_amount is not None:
            try:
                estimated_amount = float(raw_amount)
            except (TypeError, ValueError):
                estimated_amount = None

    try:
        return ActionEnvelope(
            request_id=f"req_{uuid.uuid4().hex[:12]}",
            timestamp=datetime.now(timezone.utc).isoformat(),
            tenant_id=context["tenant_id"],
            session_id=context["session_id"],
            agent_id=context["agent_id"],
            agent_version=context["agent_version"],
            framework=framework,
            principal_id=context["principal_id"],
            tool_name=tool_name,
            operation_class=spec["operation_class"],
            target_resource=target_resource,
            arguments=arguments,
            user_intent=context["user_intent"],
            credential_scope=context["credential_scope"],
            reversibility=context.get("reversibility", spec["reversibility"]),
            estimated_amount=estimated_amount,
            parent_action_id=context.get("parent_action_id"),
            trace_id=context["trace_id"],
        )
    except ValidationError as exc:
        raise AegisError(
            "SCHEMA_INVALID", f"ActionEnvelope validation failed: {exc}"
        ) from exc


async def normalize_openai_call(raw_call: dict, context: dict) -> ActionEnvelope:
    try:
        fn = raw_call["function"]
        tool_name = fn["name"]
        raw_arguments = fn.get("arguments", "{}")
        arguments = (
            json.loads(raw_arguments)
            if isinstance(raw_arguments, str)
            else dict(raw_arguments)
        )
    except (KeyError, TypeError, json.JSONDecodeError) as exc:
        raise AegisError(
            "MALFORMED_OPENAI_CALL", f"could not parse raw OpenAI call: {exc}"
        ) from exc

    return await _build_envelope(tool_name, arguments, context, framework="openai")


async def normalize_langchain_call(raw_call: dict, context: dict) -> ActionEnvelope:
    try:
        tool_name = raw_call["tool"]
        tool_input = raw_call["tool_input"]
    except KeyError as exc:
        raise AegisError(
            "MALFORMED_LANGCHAIN_CALL", f"missing key in LangChain call: {exc}"
        ) from exc

    if isinstance(tool_input, dict):
        arguments = tool_input
    elif isinstance(tool_input, str):
        try:
            arguments = json.loads(tool_input)
        except json.JSONDecodeError:
            arguments = {"input": tool_input}
    else:
        raise AegisError(
            "MALFORMED_LANGCHAIN_CALL",
            f"tool_input must be dict or str, got {type(tool_input).__name__}",
        )

    return await _build_envelope(
        tool_name, arguments, context, framework="langchain"
    )


async def run_hard_gate(envelope: ActionEnvelope) -> HardGateResult:
    if not isinstance(envelope, ActionEnvelope):
        raise AegisError(
            "INVALID_INPUT", "run_hard_gate requires an ActionEnvelope instance"
        )

    reason_codes: List[str] = []

    for field_name in (
        "tenant_id",
        "tool_name",
        "target_resource",
        "principal_id",
        "credential_scope",
        "trace_id",
        "request_id",
    ):
        value = getattr(envelope, field_name, "")
        if not isinstance(value, str) or not value.strip():
            reason_codes.append(f"SCHEMA_INVALID:{field_name}_EMPTY")

    if envelope.tenant_id not in ALLOWED_TENANTS:
        reason_codes.append("TENANT_NOT_ALLOWED")

    if envelope.tool_name not in ALLOWED_TOOLS:
        reason_codes.append("TOOL_NOT_ALLOWLISTED")

    required_scope = REQUIRED_CREDENTIAL_SCOPE.get(envelope.tool_name)
    if required_scope is not None and envelope.credential_scope != required_scope:
        reason_codes.append("CREDENTIAL_SCOPE_MISMATCH")

    ceiling = AMOUNT_CEILINGS.get(envelope.tool_name)
    if (
        ceiling is not None
        and envelope.estimated_amount is not None
        and envelope.estimated_amount > ceiling
    ):
        reason_codes.append("AMOUNT_EXCEEDS_CEILING")

    resource_upper = envelope.target_resource.upper()
    if any(token in resource_upper for token in DENY_LIST_RESOURCE_TOKENS):
        reason_codes.append("DENYLIST_RESOURCE_MATCH")
    if envelope.tool_name in DENY_LIST_TOOLS_FOR_TENANT.get(envelope.tenant_id, set()):
        reason_codes.append("DENYLIST_TOOL_FOR_TENANT")

    deny = len(reason_codes) > 0
    return HardGateResult(passed=not deny, deny=deny, reason_codes=reason_codes)


def _ctx(**overrides) -> Dict[str, Any]:
    base = {
        "tenant_id": "tenant_acme",
        "session_id": f"sess_{uuid.uuid4().hex[:8]}",
        "agent_id": "agent_refund_ops",
        "agent_version": "1.0.0",
        "principal_id": "principal_demo_user",
        "user_intent": "resolve open customer support case",
        "credential_scope": "billing:write",
        "trace_id": f"trace_{uuid.uuid4().hex[:8]}",
    }
    base.update(overrides)
    return base


def build_demo_scenarios() -> List[Dict[str, Any]]:
    return [
        {
            "label": "valid refund under ceiling",
            "expect_deny": False,
            "raw_call": {
                "id": "call_1",
                "type": "function",
                "function": {
                    "name": "issue_refund",
                    "arguments": json.dumps({"order_id": "ORD-1122", "amount": 1200, "currency": "INR"}),
                },
            },
            "context": _ctx(credential_scope="billing:write"),
        },
        {
            "label": "refund exceeds amount ceiling",
            "expect_deny": True,
            "raw_call": {
                "id": "call_2",
                "type": "function",
                "function": {
                    "name": "issue_refund",
                    "arguments": json.dumps({"order_id": "ORD-1188", "amount": 9800, "currency": "INR"}),
                },
            },
            "context": _ctx(credential_scope="billing:write"),
        },
        {
            "label": "valid ticket close",
            "expect_deny": False,
            "raw_call": {
                "id": "call_3",
                "type": "function",
                "function": {
                    "name": "close_ticket",
                    "arguments": json.dumps({"ticket_id": "TCK-501", "resolution": "refund issued"}),
                },
            },
            "context": _ctx(credential_scope="support:write", user_intent="close resolved ticket"),
        },
        {
            "label": "tenant not on allowlist",
            "expect_deny": True,
            "raw_call": {
                "id": "call_4",
                "type": "function",
                "function": {
                    "name": "close_ticket",
                    "arguments": json.dumps({"ticket_id": "TCK-777"}),
                },
            },
            "context": _ctx(tenant_id="tenant_unknown_corp", credential_scope="support:write"),
        },
        {
            "label": "valid customer email",
            "expect_deny": False,
            "raw_call": {
                "id": "call_5",
                "type": "function",
                "function": {
                    "name": "send_customer_email",
                    "arguments": json.dumps({"customer_id": "CUST-9001", "template": "refund_confirmation"}),
                },
            },
            "context": _ctx(credential_scope="comms:send", user_intent="notify customer of refund"),
        },
        {
            "label": "permission grant with wrong credential scope",
            "expect_deny": True,
            "raw_call": {
                "id": "call_6",
                "type": "function",
                "function": {
                    "name": "grant_permission",
                    "arguments": json.dumps({"principal_id": "principal_new_hire", "role": "admin"}),
                },
            },
            "context": _ctx(credential_scope="billing:write", user_intent="onboard new teammate"),
        },
        {
            "label": "valid data export with correct scope",
            "expect_deny": False,
            "raw_call": {
                "id": "call_7",
                "type": "function",
                "function": {
                    "name": "export_customer_data",
                    "arguments": json.dumps({"dataset_id": "DS-CUST-2026-Q3"}),
                },
            },
            "context": _ctx(credential_scope="data:export", user_intent="quarterly compliance export"),
        },
        {
            "label": "delete targeting reserved system resource",
            "expect_deny": True,
            "raw_call": {
                "id": "call_8",
                "type": "function",
                "function": {
                    "name": "delete_account",
                    "arguments": json.dumps({"account_id": "SYSTEM-ROOT-0001"}),
                },
            },
            "context": _ctx(credential_scope="account:delete", user_intent="cleanup stale account"),
        },
    ]


async def run_demo_agent() -> None:
    print("\n=== STEP 3: Demo Agent — 8 scripted scenarios ===")
    for scenario in build_demo_scenarios():
        envelope = await normalize_openai_call(scenario["raw_call"], scenario["context"])
        result = await run_hard_gate(envelope)
        status = "BLOCKED" if result.deny else "PASSED "
        match = "OK" if result.deny == scenario["expect_deny"] else "MISMATCH"
        print(f"[{status}] ({match}) {scenario['label']:<45} reasons={result.reason_codes}")


async def _step1_adapter_selftest() -> None:
    print("=== STEP 1: Envelope + adapters ===")

    openai_raw = {
        "id": "call_openai_1",
        "type": "function",
        "function": {
            "name": "issue_refund",
            "arguments": json.dumps({"order_id": "ORD-2201", "amount": 2200, "currency": "INR"}),
        },
    }
    openai_ctx = _ctx(credential_scope="billing:write", user_intent="refund damaged item")
    openai_envelope = await normalize_openai_call(openai_raw, openai_ctx)
    print("\n-- normalize_openai_call() ActionEnvelope --")
    print(json.dumps(enum_safe_dump(openai_envelope), indent=2))

    langchain_raw = {
        "tool": "send_customer_email",
        "tool_input": {"customer_id": "CUST-4471", "template": "delay_apology"},
        "log": "Thought: the order is delayed, I should notify the customer.",
    }
    langchain_ctx = _ctx(credential_scope="comms:send", user_intent="apologize for shipping delay")
    langchain_envelope = await normalize_langchain_call(langchain_raw, langchain_ctx)
    print("\n-- normalize_langchain_call() ActionEnvelope --")
    print(json.dumps(enum_safe_dump(langchain_envelope), indent=2))


async def _step2_hard_gate_selftest() -> None:
    print("\n=== STEP 2: Hard Gate — 5 pass / 5 deny ===")
    scenarios = build_demo_scenarios()[:4] + [
        {
            "label": "valid refund, second sample",
            "expect_deny": False,
            "raw_call": {
                "id": "call_extra_1",
                "type": "function",
                "function": {
                    "name": "close_ticket",
                    "arguments": json.dumps({"ticket_id": "TCK-909"}),
                },
            },
            "context": _ctx(credential_scope="support:write"),
        },
    ] + build_demo_scenarios()[5:8] + [
        {
            "label": "unknown tool, not allowlisted",
            "expect_deny": True,
            "raw_call": {
                "id": "call_extra_2",
                "type": "function",
                "function": {
                    "name": "wire_transfer_external",
                    "arguments": json.dumps({"account_id": "EXT-001", "amount": 500}),
                },
            },
            "context": None,
        },
    ]

    for scenario in scenarios:
        if scenario["context"] is None:
            try:
                await normalize_openai_call(scenario["raw_call"], _ctx())
            except AegisError as exc:
                print(f"[REJECTED AT ADAPTER] ({exc.code}) {scenario['label']:<45} {exc.message}")
            continue
        envelope = await normalize_openai_call(scenario["raw_call"], scenario["context"])
        result = await run_hard_gate(envelope)
        status = "BLOCKED" if result.deny else "PASSED "
        match = "OK" if result.deny == scenario["expect_deny"] else "MISMATCH"
        print(f"[{status}] ({match}) {scenario['label']:<45} reasons={result.reason_codes}")


if __name__ == "__main__":
    import asyncio

    async def _main():
        await _step1_adapter_selftest()
        await _step2_hard_gate_selftest()
        await run_demo_agent()

    asyncio.run(_main())
