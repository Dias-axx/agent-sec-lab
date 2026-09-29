# Architecture (reference design)

All components below are `ASSUMPTION`s describing a generic design used for this exercise.

## Components

| ID | Component | Responsibility |
|---|---|---|
| C1 | API gateway | Tenant authN (OIDC / API tokens), rate limiting, request validation |
| C2 | Orchestrator | Job scheduling, sandbox lifecycle, per-job credential minting |
| C3 | Agent runtime | LLM loop: builds prompts, receives model output (code + tool calls) |
| C4 | Sandbox pool | Isolated execution of untrusted code (one sandbox per job, microVM-class) |
| C5 | Tool broker | Mediates every tool call; holds credentials; enforces tool policy |
| C6 | Egress proxy | Only network path out of sandboxes; allowlist + logging |
| C7 | Data store | Tenant datasets in object storage, per-tenant prefix/bucket + key |
| C8 | Artifact store | Model/eval artifacts, write-once, content-addressed |
| C9 | Secrets manager / KMS | Platform secrets, per-tenant encryption keys |
| C10 | Audit log pipeline | Append-only, separate account, WORM retention |
| C11 | Image registry + CI/CD | Builds and signs sandbox and service images |
| C12 | Admin plane | Operator access (JIT, MFA), break-glass |
| X1 | LLM provider (third party) | Model inference |
| X2 | Third-party tool APIs / package registries | Tools reachable by agents; dependencies |
| X3 | Cloud control plane | IAM, storage, KMS, compute APIs |

## Trust boundaries

| ID | Boundary | Crossing flows |
|---|---|---|
| TB1 | Tenant ↔ Platform | Task submission, dataset upload, results download, tenant API tokens |
| TB2 | Sandbox ↔ Host / platform internals | Untrusted code execution, syscalls, sandbox networking, tool calls to C5 |
| TB3 | Platform ↔ Cloud control plane | Workload identities calling IAM/storage/KMS; image deploys; log writes |
| TB4 | Platform ↔ Third parties | Prompts/data to LLM provider, tool API calls, package installs via egress |
| TB5 | Operator ↔ Platform | Administrative access, deployments, break-glass |

## Design principles (target state)

- Treat **all** model output and all data processed by the agent as untrusted input.
- Credentials never enter the sandbox; the tool broker acts on the agent's behalf.
- Deny-by-default egress; the sandbox has no route to internal services or metadata endpoints.
- Tenant identity comes from the authenticated context, never from request parameters.
- Audit logs are written to a separate account the platform's workload identities cannot modify.

## Key flows

| ID | Flow | Boundaries |
|---|---|---|
| F1 | Tenant submits task + dataset reference via C1 | TB1 |
| F2 | C2 creates sandbox in C4 and mints short-lived job credential | TB2, TB3 |
| F3 | C3 sends prompt (may include dataset excerpts) to X1; receives code/tool calls | TB4 |
| F4 | Code runs in C4; reads dataset via scoped credential | TB2, TB3 |
| F5 | Agent tool call → C5 → X2 | TB2, TB4 |
| F6 | Sandbox network egress via C6 (package installs, allowed hosts) | TB2, TB4 |
| F7 | Results/artifacts written to C8; returned to tenant | TB1, TB3 |
| F8 | All components emit audit events to C10 | TB3 |
| F9 | CI/CD builds, signs, deploys images from C11 | TB3, TB4 |
| F10 | Operator administers platform via C12 | TB5 |
| F11 | Retention job deletes/crypto-shreds data per contract term | TB3 |
