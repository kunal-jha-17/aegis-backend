"""
Run against your server (local or deployed) and check every scenario
Aditya's integration brief requires. Usage:
    BASE_URL=https://your-deployed-url python3 test_demo.py
    (or just run it as-is to test http://localhost:8000)
"""
import os
import uuid
import httpx

BASE_URL = os.environ.get("BASE_URL", "http://localhost:8000")
client = httpx.Client(base_url=BASE_URL, timeout=15)

results = []


def check(name, condition, detail=""):
    status = "PASS" if condition else "FAIL"
    results.append((name, status, detail))
    print(f"[{status}] {name}" + (f"  — {detail}" if detail else ""))


def envelope(tenant_id, agent_id, framework, order_id, amount, extra_args=None):
    return {
        "request_id": f"req_{uuid.uuid4().hex[:8]}",
        "timestamp": "2026-09-20T09:30:00.000Z",
        "tenant_id": tenant_id,
        "session_id": "sess_demo_1",
        "agent_id": agent_id,
        "agent_version": "1.0.0",
        "framework": framework,
        "principal_id": "user_demo",
        "tool_name": "issue_refund",
        "operation_class": "write",
        "target_resource": f"Order {order_id}",
        "arguments": {"order_id": order_id, "amount": amount, "currency": "INR", **(extra_args or {})},
        "user_intent": "refund for delay",
        "credential_scope": "refunds:write",
        "reversibility": "irreversible",
        "estimated_amount": amount,
        "parent_action_id": None,
        "trace_id": f"trace_{uuid.uuid4().hex[:8]}",
    }


# 0. health check
r = client.get("/healthz")
check("server is up", r.status_code == 200, r.text)

# A. 4200 refund, standard customer -> BLOCK, exposure ~3200
envA = envelope("acme-in", "refund-bot", "langchain", "ORD-A001", 4200)
r = client.post("/v1/evaluate", json=envA)
dA = r.json()
check("A: status 200", r.status_code == 200, str(dA)[:200])
check("A: verdict BLOCK", dA.get("verdict") == "BLOCK", dA.get("verdict"))
check("A: exposure 3200", dA.get("estimated_exposure") == 3200, dA.get("estimated_exposure"))
check("A: has policy_ids", len(dA.get("policy_ids", [])) > 0, dA.get("policy_ids"))

# B. 850 refund -> ALLOW
envB = envelope("acme-in", "refund-bot", "langchain", "ORD-B001", 850)
r = client.post("/v1/evaluate", json=envB)
dB = r.json()
check("B: verdict ALLOW", dB.get("verdict") == "ALLOW", dB.get("verdict"))

# C. 1500 VIP refund -> FLAG, required_approval, review_id present
envC = envelope("acme-in", "refund-bot", "langchain", "ORD-C001", 1500, {"customer_tier": "vip"})
r = client.post("/v1/evaluate", json=envC)
dC = r.json()
check("C: verdict FLAG", dC.get("verdict") == "FLAG", dC.get("verdict"))
check("C: required_approval true", dC.get("required_approval") is True)
check("C: review_id present", "review_id" in dC, dC.get("review_id"))

# C2. resolve C as approved -> ALLOW + new precedent_id
if "review_id" in dC:
    r = client.post(f"/v1/reviews/{dC['review_id']}/resolve", json={
        "outcome": "approved", "reviewer_id": "kunal", "reason": "VIP customer, late delivery",
    })
    dC2 = r.json()
    check("C2: verdict ALLOW after approve", dC2.get("verdict") == "ALLOW", dC2.get("verdict"))
    check("C2: precedent_ids non-empty", len(dC2.get("precedent_ids", [])) > 0, dC2.get("precedent_ids"))
else:
    check("C2: skipped, no review_id from C", False)

# D. another 1500 VIP refund, same tenant/agent, different order -> ALLOW via precedent
envD = envelope("acme-in", "refund-bot", "langchain", "ORD-D999", 1500, {"customer_tier": "vip"})
r = client.post("/v1/evaluate", json=envD)
dD = r.json()
check("D: verdict ALLOW (precedent matched)", dD.get("verdict") == "ALLOW", dD.get("verdict"))
check("D: precedent_ids non-empty", len(dD.get("precedent_ids", [])) > 0, dD.get("precedent_ids"))

# E. same 1500 VIP refund, DIFFERENT tenant/agent -> must FLAG, never ALLOW, no precedent
envE = envelope("globex-us", "support-agent", "openai", "ORD-E001", 1500, {"customer_tier": "vip"})
r = client.post("/v1/evaluate", json=envE)
dE = r.json()
check("E: verdict is NOT ALLOW", dE.get("verdict") != "ALLOW", dE.get("verdict"))
check("E: precedent_ids empty (scope isolation holds)", len(dE.get("precedent_ids", [])) == 0, dE.get("precedent_ids"))

# R. replay scenario A
r = client.post("/v1/replay", json={"decision_hash": dA["decision_hash"]})
if r.status_code == 200:
    dR = r.json()
    check("Replay A matches original", dR.get("decision_hash") == dA.get("decision_hash"))
else:
    check("Replay A", False, f"status {r.status_code}: {r.text[:200]}")

print("\n" + "=" * 50)
passed = sum(1 for _, s, _ in results if s == "PASS")
print(f"{passed}/{len(results)} checks passed")
if passed < len(results):
    print("Failures above — paste them to me with the 'detail' shown and I'll pinpoint the exact fix.")
