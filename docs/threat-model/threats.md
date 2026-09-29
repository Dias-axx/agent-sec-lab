# Threats

STRIDE: **S**poofing, **T**ampering, **R**epudiation, **I**nformation disclosure,
**D**enial of service, **E**levation of privilege. L = likelihood, I = impact (L/M/H).
Residual = rating after proposed mitigations ([mitigations.md](mitigations.md)).
ATT&CK IDs reference MITRE ATT&CK Enterprise; `ATLAS AML.T0051` = MITRE ATLAS
"LLM Prompt Injection".

| ID | Boundary / flow | STRIDE | ATT&CK / ATLAS | Description | L | I | Mitigations | Detection signal | Residual |
|---|---|---|---|---|---|---|---|---|---|
| T-01 | TB2 / F4 | E | T1611, T1068 | Untrusted code exploits a kernel or hypervisor vulnerability to escape the sandbox to the host | M | H | M-01, M-02 | Unexpected host processes/syscalls from sandbox cgroups; seccomp violations; runtime-security alerts (e.g. eBPF-based) | M |
| T-02 | TB2 / F2 | E | T1611, T1610 | Sandbox misconfiguration (privileged mode, host mounts, runtime socket, excess capabilities) enables escape | M | H | M-01 | Admission-policy denials; config drift scans of sandbox specs | L |
| T-03 | TB2→TB3 / F6 | I, E | T1552.005 | Sandbox code queries the cloud instance metadata endpoint and obtains node/workload credentials | H | H | M-03, M-22 | Egress/flow logs showing link-local metadata IP from sandbox network; cloud API calls from node identity outside expected set | L |
| T-04 | TB1 / F1, F7 | I | T1530 | Cross-tenant data access through IDOR / tenant ID taken from request parameters or shared storage prefixes | M | H | M-06 | Storage access logs where job tenant ≠ object tenant; authz-denial spikes | L |
| T-05 | TB2 / F2 | I | no direct mapping | Residual data from a previous tenant in reused sandboxes, warm pools, or scratch volumes | M | H | M-01 | Sandbox reuse counter > 1; scratch volume not wiped at teardown (lifecycle audit) | L |
| T-06 | TB2 | I | no direct mapping | Side-channel leakage between co-located tenants (shared CPU caches, timing) | L | H | M-01, M-02 | Hard to detect; monitor co-location policy compliance | M |
| T-07 | TB2→TB4 / F5 | I | T1552, T1567 | Agent obtains a platform secret via a tool call (tool returns secret, env var, or config) and exfiltrates it | M | H | M-04, M-08 | Secret-pattern detection on tool outputs and egress payloads; use of a credential from unexpected source IP | M |
| T-08 | TB2→TB4 / F6 | I | T1048, T1071.004 | Customer dataset exfiltrated via HTTP to attacker host or DNS tunnelling | H | H | M-03 | Egress proxy denies to non-allowlisted hosts; DNS query entropy/volume anomalies; large egress per job | M |
| T-09 | TB4→TB2 / F3, F5 | E, T | ATLAS AML.T0051 | Prompt injection embedded in customer data or tool output steers the agent to invoke privileged tools | H | H | M-05 | Tool-call sequences deviating from task profile; policy-engine denials; high-impact actions pending approval | M |
| T-10 | TB4 / F5 | I | ATLAS AML.T0051, T1567 | Prompt injection makes the agent send data to an attacker-controlled destination via an allowed tool (e.g. web fetch with data in URL) | H | H | M-03, M-04, M-05 | Outbound URLs containing high-entropy/data-like query strings; destinations first seen | M |
| T-11 | TB2 / F4 | D | T1496 | Malicious tenant uses sandboxes for cryptomining or other resource abuse | H | M | M-09 | CPU saturation per job; connections to mining pools (blocked by egress); cost anomaly alerts | L |
| T-12 | TB1, TB2 | D | T1499 | Fork bombs, oversized jobs, or API floods exhaust orchestrator/sandbox capacity | M | M | M-09 | Queue depth and scheduling latency; pids limit hits; rate-limit rejections | L |
| T-13 | TB1 / F1 | S | T1528, T1078 | Stolen tenant API token replayed to access the tenant's data and jobs | M | H | M-08, M-10 | Token use from new ASN/geo; concurrent use from distinct clients; leaked-token scanning hits | M |
| T-14 | TB1 / F1 | S, E | T1190 | Broken authN/authZ (JWT audience/issuer not validated, role confusion) lets attacker act as another tenant | L | H | M-10 | Authz test failures in CI; token validation errors; requests with mismatched tenant claims | L |
| T-15 | TB3 / F11 | I | no direct mapping | Data retained beyond contract term in backups, caches, logs, or scratch storage | M | H | M-13 | Inventory scan for objects older than TTL; lifecycle-policy drift; deletion job failures | M |
| T-16 | TB3 / F11 | R | no direct mapping | Deletion performed but not provable; platform cannot evidence deletion to customer/auditor | M | M | M-11, M-13 | Missing deletion receipts per tenant/dataset; retention job without audit event | L |
| T-17 | TB4 / F3 | I | no direct mapping | Customer data sent to LLM provider is retained or used for training contrary to contract terms | M | H | M-14 | Provider configuration review; data-flow inventory shows datasets to providers without approved terms | M |
| T-18 | TB4 / F9 | T | T1195.001 | Compromised dependency in the agent runtime or sandbox base image | M | H | M-15, M-16 | Dependency audit findings; SBOM diff on unexpected new packages; runtime anomaly in trusted components | M |
| T-19 | TB4 / F6 | T, E | T1195.001 | Agent code installs typosquatted or malicious packages at runtime | H | M | M-03, M-15 | Package installs outside mirror/allowlist (proxy denials); install-script network activity | L |
| T-20 | TB3 / F9 | T | T1525, T1195.002 | Tampered or unsigned image deployed to sandbox or service nodes | L | H | M-16 | Admission controller signature-verification failures; image digest not in release manifest | L |
| T-21 | TB3 / F9 | T, E | T1195.002 | CI/CD compromise via unpinned third-party actions or over-privileged workflow tokens | M | H | M-17 | agentsec SC-01 / AC-03 FAIL; workflow changes without CODEOWNERS review; unexpected OIDC token exchanges | L |
| T-22 | TB3 / F8 | R, T | T1070, T1562.008 | Insider or compromised identity deletes/modifies audit logs or disables log delivery | L | H | M-11 | Gap in log sequence / hash-chain break; cloud audit event for logging config change; delivery heartbeat missing | L |
| T-23 | TB2 / F8 | R | no direct mapping | Sandbox actions not attributable to tenant/job/identity; investigation impossible | M | M | M-11, M-12 | Log records missing tenant/job fields (schema validation in pipeline) | L |
| T-24 | TB3 / F2, F4 | E | T1078.004 | Orchestrator or runtime identity has broad permissions (reads all tenants' data) and becomes the high-value target | M | H | M-06, M-07 | IAM analyzer: unused/wildcard permissions; data access by service identity outside job context | L |
| T-25 | TB3 | I, S | T1552.001 | Long-lived static cloud keys stored in config/repos are leaked | M | H | M-07, M-08 | Secret-scanning alerts (agentsec DP-01); key age reports; use of key from unexpected location | L |
| T-26 | TB5 / F10 | I | T1078 | Malicious insider uses standing production access to read customer data | L | H | M-07, M-18 | Access without approved JIT ticket; bulk data reads by human identities; session recording review | M |
| T-27 | TB5 / F10 | S | T1078, T1110 | Admin account takeover via phishing or credential stuffing (no phishing-resistant MFA) | M | H | M-18 | Impossible travel; MFA fatigue patterns; new device registration on admin accounts | L |
| T-28 | TB3 / F7 | T | T1565 | Tampering with model/eval artifacts to falsify evaluation results | L | M | M-19 | Hash mismatch on artifact read; write attempts to write-once store | L |
| T-29 | TB1 / F1 | I | no direct mapping | Verbose errors or APIs leak tenant metadata, internal paths, or enable tenant enumeration | M | L | M-20 | Error responses containing stack traces (DAST); enumeration patterns (sequential IDs, 404 vs 403 probing) | L |
| T-30 | TB4 / F3, F5 | D | no direct mapping | Agent loops or abuse exhaust the platform's third-party API quota/budget (denial of wallet) | M | M | M-04, M-09 | Per-tenant token/cost budget alarms; call-rate anomalies per job | L |
| T-31 | TB4 / F3, F5 | I, T | T1557 | Interception or manipulation of traffic to third-party APIs (TLS validation disabled, rogue proxy) | L | H | M-21 | TLS handshake failures/cert pin mismatches; code scanning for disabled verification | L |
| T-32 | TB2 / F6 | E | T1210 | Lateral movement from sandbox to internal services (east-west) | M | H | M-02, M-03, M-22 | Denied flows from sandbox CIDR to internal CIDRs; mTLS authz denials | L |
| T-33 | TB3 | I | T1078.004 | Overly broad KMS key policy lets one identity decrypt all tenants' data | L | H | M-06, M-07 | KMS decrypt events where key tenant ≠ job tenant; key policy drift | L |
