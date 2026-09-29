# Threat model — untrusted agent-code execution platform

> Lab exercise. The system is a **generic reference design**, not a description of any real
> product or employer environment. Statements about the design are `ASSUMPTION`s unless noted.

## Scope

A multi-tenant platform that:

1. accepts tasks from tenants (API),
2. has an LLM produce agent code / tool calls,
3. executes that **untrusted** code in per-job sandboxes, and
4. processes customer-provided or licensed datasets during execution.

Out of scope: the LLM provider's internal security, physical security, end-user devices,
billing, and the tenant's own environment.

## Method

- System decomposition and trust boundaries → [architecture.md](architecture.md)
- Data-flow diagram (Mermaid) → [dfd.md](dfd.md)
- **STRIDE** applied per trust boundary and flow → [threats.md](threats.md)
- MITRE ATT&CK technique IDs where a technique fits; MITRE ATLAS for LLM-specific threats;
  `no direct mapping` otherwise.
- Mitigations mapped to threat IDs, with residual risk → [mitigations.md](mitigations.md)
- Rating: Likelihood (L) and Impact (I) on a 3-point scale (Low / Medium / High),
  qualitative, based on the reference design. Risk = the higher-weighted combination;
  any `H` impact is treated as high priority.

Consistency is enforced by `tests/test_threat_model.py` (≥ 25 threats, unique IDs, no orphan
mitigations, every high-rated threat has a detection signal, cross-references match).

## Assets

| ID | Asset | Why it matters |
|---|---|---|
| A1 | Customer datasets (provided / licensed) | Confidentiality, contractual use limits, retention terms |
| A2 | Model and evaluation artifacts | Integrity of results; IP |
| A3 | Platform secrets (API keys, cloud credentials, signing keys) | Enable every other compromise |
| A4 | Tenant metadata (accounts, job history, config) | Privacy, enumeration, targeting |
| A5 | Audit logs | Accountability, forensics, compliance evidence |
| A6 | Compute capacity / third-party API quota | Cost and availability |

## Threat actors

| Actor | Capability / intent |
|---|---|
| Malicious tenant | Legitimate account; submits hostile code on purpose (escape, cross-tenant access, abuse) |
| Compromised agent / model output | Benign tenant, but the LLM is steered by prompt injection in data or tool output |
| External attacker | No account; targets public API, stolen credentials, or the supply chain |
| Malicious insider | Operator with production access |
| Compromised dependency | Third-party package, base image, or CI action carrying malicious code |

## Summary

- 33 threats across 5 trust boundaries ([threats.md](threats.md)).
- Highest-rated areas: sandbox escape and metadata-credential theft (TB2/TB3), secret and
  data exfiltration through agent tool calls and egress (TB4), prompt injection leading to
  tool abuse (no complete technical fix exists), and retention/deletion vs. contract terms.
- 22 mitigations ([mitigations.md](mitigations.md)). Several are directly checkable by the
  controls-as-code tool in this repo (SC-01, AC-03, CM-01, CM-02, DP-01, AC-01).
- Residual risk remains **Medium** for prompt-injection-driven tool abuse and for zero-day
  sandbox escape; see [mitigations.md § Residual risk](mitigations.md#residual-risk).
