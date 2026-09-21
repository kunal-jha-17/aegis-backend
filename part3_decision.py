"""
TEAM CRYPTIX — AEGIS BACKEND — PART 3 OF 4
Risk, Decision & Impact Engine

Modified after integration testing (see "Integration tuning" notes in decide()):
BLOCK now needs the request to be at least BLOCK_MIN_CEILING_RATIO x the policy
ceiling, and the low-confidence FLAG is waived for clearly in-policy requests.
Function signatures are unchanged. Verified during integration: this is the
ONE part whose function signatures exactly match what the original brief
specified (compute_risk(envelope, evidence), compute_impact(envelope, risk),
decide(envelope, evidence, hard_gate, risk, impact)) — Part 4 guessed
different signatures for these three (see part4_human_audit.py's merge
notes for the fix), not this file.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from shared_contracts import (
    ActionEnvelope,
    Decision,
    EvidenceBundle,
    EvidenceItem,
    HardGateResult,
    ImpactEstimate,
    OperationClass,
    RiskAssessment,
    Verdict,
    AegisError,
)

POLICY_VERSION = "part3-v1"

HIGH_RISK_THRESHOLD = 0.70
UNCERTAIN_CONFIDENCE_THRESHOLD = 0.50
HIGH_IMPACT_THRESHOLD = 10_000.0
# A request must exceed the matched policy ceiling by at least this multiple to be auto-BLOCKed;
# between 1x and this multiple it is FLAGged for human review (e.g. 1,500 vs a 1,000 ceiling).
BLOCK_MIN_CEILING_RATIO = 2.0
HIGH_ABSOLUTE_AMOUNT_THRESHOLD = 500_000.0
FLAG_REVIEW_WINDOW_HOURS = 24

_REVERSIBILITY_RISK = {
    "irreversible": 0.30,
    "partial": 0.12,
    "reversible": 0.0,
}

_SENSITIVE_OPERATIONS = {
    OperationClass.DELETE,
    OperationClass.EXPORT,
    OperationClass.PERMISSION_CHANGE,
}

_NUMBER_RE = re.compile(r"[\d,]+(?:\.\d+)?")


def _extract_policy_ceiling(policy_matches: List[EvidenceItem]) -> Optional[float]:
    if not policy_matches:
        return None
    best = max(policy_matches, key=lambda e: e.score)
    found = _NUMBER_RE.findall(best.text)
    if not found:
        return None
    try:
        return float(found[0].replace(",", ""))
    except ValueError:
        return None


def _ceiling_from_flags(anomaly_flags: List[str]) -> Optional[float]:
    for flag in anomaly_flags:
        if flag.startswith("ceiling_ref:"):
            try:
                return float(flag.split(":", 1)[1])
            except ValueError:
                return None
    return None


def _ratio_from_flags(anomaly_flags: List[str]) -> Optional[float]:
    for flag in anomaly_flags:
        if flag.startswith("amount_exceeds_policy_ceiling:ratio="):
            try:
                return float(flag.split("ratio=", 1)[1])
            except ValueError:
                return None
    return None


def _stable_serialize(obj) -> dict:
    return obj.model_dump(mode="json")


async def compute_risk(envelope: ActionEnvelope, evidence: EvidenceBundle) -> RiskAssessment:
    try:
        anomaly_flags: List[str] = []
        amount = envelope.estimated_amount
        ceiling = _extract_policy_ceiling(evidence.policy_matches)

        amount_component = 0.0
        if amount is not None and ceiling is not None and ceiling > 0:
            ratio = amount / ceiling
            amount_component = min(ratio, 3.0) / 3.0 * 0.6
            anomaly_flags.append(f"ceiling_ref:{ceiling}")
            if ratio > 1.0:
                anomaly_flags.append(f"amount_exceeds_policy_ceiling:ratio={ratio:.2f}")
        elif amount is not None and ceiling is None:
            amount_component = 0.3
            anomaly_flags.append("no_policy_ceiling_found")

        reversibility_component = _REVERSIBILITY_RISK.get(envelope.reversibility, 0.15)
        if envelope.reversibility not in _REVERSIBILITY_RISK:
            anomaly_flags.append(f"unrecognized_reversibility:{envelope.reversibility}")

        if envelope.operation_class in _SENSITIVE_OPERATIONS:
            anomaly_flags.append(f"sensitive_operation_class:{envelope.operation_class.value}")

        if not evidence.precedent_matches:
            anomaly_flags.append("no_precedent_history")

        if amount is not None and amount > HIGH_ABSOLUTE_AMOUNT_THRESHOLD:
            anomaly_flags.append(f"high_absolute_amount:{amount:g}")

        scored_flags = [f for f in anomaly_flags if not f.startswith("ceiling_ref:")]
        anomaly_component = min(len(scored_flags) * 0.05, 0.20)

        risk_score = amount_component + reversibility_component + anomaly_component
        risk_score = max(0.0, min(1.0, risk_score))

        all_scores = [e.score for e in evidence.policy_matches] + [
            e.score for e in evidence.precedent_matches
        ]
        if all_scores:
            confidence = max(0.0, min(1.0, sum(all_scores) / len(all_scores)))
        else:
            confidence = 0.3

        if envelope.reversibility == "irreversible" and amount is None:
            if confidence > 0.4:
                anomaly_flags.append("irreversible_unquantified_impact")
            confidence = min(confidence, 0.4)

        return RiskAssessment(
            risk_score=round(risk_score, 4),
            confidence=round(confidence, 4),
            reversibility=envelope.reversibility,
            anomaly_flags=anomaly_flags,
        )
    except AegisError:
        raise
    except Exception as exc:
        raise AegisError("RISK_COMPUTATION_FAILED", str(exc)) from exc


async def compute_impact(envelope: ActionEnvelope, risk: RiskAssessment) -> ImpactEstimate:
    try:
        amount = envelope.estimated_amount

        if amount is None:
            return ImpactEstimate(
                estimated_exposure=None,
                calculation="no estimated_amount on envelope; exposure not quantifiable",
            )

        ceiling = _ceiling_from_flags(risk.anomaly_flags)

        if ceiling is not None:
            exposure = amount - ceiling
            calculation = (
                f"estimated_amount ({amount:g}) minus policy ceiling ({ceiling:g}) "
                f"= {exposure:g} INR exposure"
            )
            if exposure < 0:
                exposure = 0.0
                calculation += " (clamped to 0 — within ceiling, no exposure)"
        else:
            exposure = round(amount * risk.risk_score, 2)
            calculation = (
                f"estimated_amount ({amount:g}) * risk_score ({risk.risk_score:.2f}) "
                f"= {exposure:g} INR exposure (no policy ceiling found in evidence)"
            )

        return ImpactEstimate(estimated_exposure=exposure, calculation=calculation)
    except AegisError:
        raise
    except Exception as exc:
        raise AegisError("IMPACT_COMPUTATION_FAILED", str(exc)) from exc


async def decide(
    envelope: ActionEnvelope,
    evidence: EvidenceBundle,
    hard_gate: HardGateResult,
    risk: RiskAssessment,
    impact: ImpactEstimate,
) -> Decision:
    start = time.perf_counter()
    try:
        policy_ids = [e.id for e in evidence.policy_matches]
        precedent_ids = [e.id for e in evidence.precedent_matches]
        evidence_ids = policy_ids + precedent_ids

        policy_conflict = any(
            f.startswith("amount_exceeds_policy_ceiling") for f in risk.anomaly_flags
        )
        ceiling_ratio = _ratio_from_flags(risk.anomaly_flags)
        # Integration tuning: "within ceiling" = a ceiling was found (ceiling_ref flag), the request does not
        # exceed it, risk is below the high-risk threshold and the operation is not a sensitive one. Retrieval
        # confidence is a weak signal for such requests, so it must not force a human review on its own.
        within_ceiling = (
            _ceiling_from_flags(risk.anomaly_flags) is not None
            and not policy_conflict
            and risk.risk_score < HIGH_RISK_THRESHOLD
            and not any(f.startswith("sensitive_operation_class") for f in risk.anomaly_flags)
        )
        precedent_approves = any(
            e.text.startswith("[PRECEDENT outcome=approved]") for e in evidence.precedent_matches
        )
        precedent_rejects = any(
            e.text.startswith("[PRECEDENT outcome=rejected]") for e in evidence.precedent_matches
        )

        reason_codes: List[str] = []

        if hard_gate.deny:
            verdict = Verdict.BLOCK
            required_approval = False
            reason_codes.extend(hard_gate.reason_codes or ["hard_gate_denied"])
            human_explanation = (
                "Blocked: request failed a mandatory hard gate check ("
                + ", ".join(hard_gate.reason_codes or ["unspecified"])
                + ")."
            )

        elif precedent_rejects:
            verdict = Verdict.BLOCK
            required_approval = False
            reason_codes.append("precedent_rejects_this_pattern")
            human_explanation = "Blocked: a prior human review rejected this exact pattern."

        elif precedent_approves:
            verdict = Verdict.ALLOW
            required_approval = False
            reason_codes.append("precedent_approves_this_pattern")
            human_explanation = "Allowed: matches a precedent a human previously approved."

        elif (
            risk.risk_score >= HIGH_RISK_THRESHOLD
            and policy_conflict
            and (ceiling_ratio is None or ceiling_ratio >= BLOCK_MIN_CEILING_RATIO)
        ):
            verdict = Verdict.BLOCK
            required_approval = False
            reason_codes.append("high_risk_policy_conflict")
            human_explanation = (
                f"Blocked: risk score {risk.risk_score:.2f} is at or above the "
                f"{HIGH_RISK_THRESHOLD:.2f} threshold and the request exceeds a "
                f"matched policy ceiling."
            )

        elif policy_conflict or (
            risk.confidence < UNCERTAIN_CONFIDENCE_THRESHOLD and not within_ceiling
        ) or (
            impact.estimated_exposure is not None
            and impact.estimated_exposure >= HIGH_IMPACT_THRESHOLD
        ):
            verdict = Verdict.FLAG
            required_approval = True
            reason_codes.append("uncertain_or_high_impact")
            if policy_conflict:
                ratio_txt = f"{ceiling_ratio:.2f}x " if ceiling_ratio is not None else ""
                human_explanation = (
                    f"Flagged for human review: the request is {ratio_txt}the matched policy ceiling "
                    f"(estimated exposure {impact.estimated_exposure}), below the auto-block level, "
                    f"so a human decision is required."
                )
            else:
                human_explanation = (
                    f"Flagged for human review: confidence {risk.confidence:.2f} "
                    f"(threshold {UNCERTAIN_CONFIDENCE_THRESHOLD:.2f}), estimated "
                    f"exposure {impact.estimated_exposure}."
                )

        else:
            verdict = Verdict.ALLOW
            required_approval = False
            reason_codes.append("clean_allow")
            human_explanation = (
                f"Allowed: risk score {risk.risk_score:.2f} within tolerance, "
                f"no policy conflicts detected."
            )

        if hard_gate.reason_codes:
            for rc in hard_gate.reason_codes:
                if rc not in reason_codes:
                    reason_codes.append(rc)

        hash_payload = {
            "envelope": _stable_serialize(envelope),
            "policy_ids": sorted(policy_ids),
            "precedent_ids": sorted(precedent_ids),
            "hard_gate": _stable_serialize(hard_gate),
            "risk": _stable_serialize(risk),
            "impact": _stable_serialize(impact),
            "policy_version": POLICY_VERSION,
        }
        serialized = json.dumps(hash_payload, sort_keys=True, separators=(",", ":"))
        decision_hash = hashlib.sha256(serialized.encode("utf-8")).hexdigest()

        replay_token = hashlib.sha256(
            f"{envelope.request_id}:{decision_hash}".encode("utf-8")
        ).hexdigest()[:32]

        expires_at: Optional[str] = None
        if verdict == Verdict.FLAG:
            expires_at = (
                datetime.now(timezone.utc) + timedelta(hours=FLAG_REVIEW_WINDOW_HOURS)
            ).isoformat()

        latency_ms = (time.perf_counter() - start) * 1000.0

        return Decision(
            request_id=envelope.request_id,
            verdict=verdict,
            reason_codes=reason_codes,
            human_explanation=human_explanation,
            policy_ids=policy_ids,
            evidence_ids=evidence_ids,
            precedent_ids=precedent_ids,
            risk_score=risk.risk_score,
            confidence=risk.confidence,
            estimated_exposure=impact.estimated_exposure,
            calculation=impact.calculation,
            required_approval=required_approval,
            latency_ms=round(latency_ms, 4),
            policy_version=POLICY_VERSION,
            decision_hash=decision_hash,
            expires_at=expires_at,
            replay_token=replay_token,
        )
    except AegisError:
        raise
    except Exception as exc:
        raise AegisError("DECISION_ASSEMBLY_FAILED", str(exc)) from exc


def build_denied_decision(envelope: ActionEnvelope, hard_gate: HardGateResult) -> Decision:
    """
    NEW — added during integration, not in any part's original brief.
    main.py needs a way to turn a hard-gate denial straight into a BLOCK
    Decision without a wasted round-trip through evidence retrieval and
    risk scoring (there's no evidence to fetch for a request that's
    already deterministically denied). This mirrors decide()'s BLOCK path
    exactly, with empty evidence/risk/impact since none were computed.
    """
    empty_risk = RiskAssessment(risk_score=1.0, confidence=1.0, reversibility=envelope.reversibility, anomaly_flags=[])
    empty_impact = ImpactEstimate(estimated_exposure=None, calculation="not computed — denied at hard gate")
    hash_payload = {
        "envelope": _stable_serialize(envelope),
        "hard_gate": _stable_serialize(hard_gate),
        "policy_version": POLICY_VERSION,
    }
    decision_hash = hashlib.sha256(
        json.dumps(hash_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return Decision(
        request_id=envelope.request_id,
        verdict=Verdict.BLOCK,
        reason_codes=hard_gate.reason_codes or ["hard_gate_denied"],
        human_explanation="Blocked: request failed a mandatory hard gate check ("
        + ", ".join(hard_gate.reason_codes or ["unspecified"]) + ").",
        policy_ids=[], evidence_ids=[], precedent_ids=[],
        risk_score=empty_risk.risk_score, confidence=empty_risk.confidence,
        estimated_exposure=None, calculation=empty_impact.calculation,
        required_approval=False, latency_ms=0.0, policy_version=POLICY_VERSION,
        decision_hash=decision_hash, expires_at=None,
        replay_token=hashlib.sha256(f"{envelope.request_id}:{decision_hash}".encode()).hexdigest()[:32],
    )
