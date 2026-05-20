# AGENTS.md

# HELIX SENTINEL — OPERATIONAL ENGINEERING RULES

You are working inside an already mature security analytics and SOC operations platform.

Project name:

* Helix Sentinel

Architecture status:

* modular monolith
* operationally coherent
* production-oriented
* additive-first
* security-focused
* observability-first
* deterministic
* repository-backed
* low-risk incremental evolution only

The repository is already:

* professionally presentable
* recruiter-ready
* close to public-release maturity

The primary engineering risks are now:

* architectural drift
* unnecessary complexity
* dependency churn
* overengineering
* speculative refactors
* inconsistent operational behavior
* frontend ecosystem instability
* CI/security workflow regressions

---

# PROJECT PHILOSOPHY

Helix Sentinel intentionally avoids:

* microservices
* realtime streaming systems
* websocket infrastructure
* graph engines
* SIEM query languages
* speculative AI systems
* governance/compliance platform inflation
* fake-enterprise abstractions
* orchestration sprawl
* unnecessary frameworks

Helix Sentinel intentionally prioritizes:

* operational realism
* deterministic workflows
* maintainability-first engineering
* typed backend engineering
* security-first architecture
* auditability
* observability
* repository-backed persistence
* pragmatic SOC workflows
* low operational risk
* predictable runtime behavior

---

# GLOBAL RULES

Always:
- preserve modular monolith architecture
- preserve deterministic workflows
- preserve observability semantics
- preserve auditability
- preserve tenant isolation
- preserve CI/security posture
- minimize token usage
- minimize file churn
- minimize dependency churn

Do NOT:
- redesign architecture
- introduce new infrastructure
- introduce realtime systems
- introduce websocket behavior
- introduce framework migrations
- repeatedly refactor stable files
- perform speculative modernization

Automated tests are NOT the default priority.
Run only lightweight targeted validation if strictly necessary.

---

# ARCHITECTURE RULES

The architecture is intentionally stable.

NEVER:

* redesign architecture
* introduce distributed systems
* create parallel orchestration layers
* duplicate repository systems
* duplicate analytics pipelines
* duplicate observability systems
* create speculative abstractions
* replace stable infrastructure unnecessarily
* introduce hidden execution flows
* create broad framework migrations
* introduce architectural inflation

ALWAYS:

* reuse existing infrastructure
* reuse repository contracts
* reuse observability patterns
* reuse middleware
* reuse validation patterns
* reuse typed DTO/schema patterns
* preserve deterministic behavior
* preserve auditability
* preserve tenant isolation semantics
* preserve operational consistency
* preserve existing runtime contracts

---

# ACTIVE ARCHITECTURE UNDERSTANDING

Current authoritative backend runtime:

* backend/helix_sentinel/main.py

Current authoritative SQLAlchemy metadata owner:

* helix_sentinel.db.base.Base

Current active feature domains mostly live under:

* backend/app/*

Platform/foundation modules mostly live under:

* backend/helix_sentinel/*

The app/* versus helix_sentinel/* split is a KNOWN architectural constraint.

DO NOT:

* perform large namespace consolidations
* perform broad domain migrations
* attempt architecture cleanup for aesthetics

Only touch those areas if:

* operationally necessary
* explicitly requested
* low-risk
* incremental

---

# SECURITY RULES

Security posture is critical.

Preserve:

* RBAC semantics
* tenant scoping
* audit logging
* correlation IDs
* structured logging
* no-secret logging posture
* Semgrep enforcement
* Gitleaks enforcement
* CI security workflows
* deterministic validation behavior

DO NOT:

* weaken Semgrep rules globally
* disable security workflows
* bypass CI enforcement
* log secrets/tokens/credentials
* introduce permissive auth behavior
* expose tenant data
* store tokens client-side
* remove audit events
* introduce unsafe dynamic queries

Treat these as sensitive:

* authorization headers
* tokens
* credentials
* secrets
* tenant identifiers
* raw customer payloads
* telemetry that could identify customers

---

# FRONTEND RULES

Frontend philosophy:

* operational dashboard
* not a marketing site
* not a consumer UI
* not a realtime SIEM

Preserve:

* server-rendered Next.js flow
* typed API client
* operational readability
* lightweight UX
* bounded investigation workflows
* maintainability-first structure

DO NOT:

* introduce Redux/global-state frameworks
* introduce websocket/realtime systems
* introduce charting-framework sprawl
* introduce frontend overengineering
* introduce excessive animation
* redesign the frontend architecture casually

The frontend must continue feeling like:

* a pragmatic SOC workbench
* an analyst operations surface
* an engineering-focused dashboard

---

# BACKEND RULES

Preserve:

* FastAPI app factory structure
* repository-backed persistence
* SQLAlchemy expression-based queries
* async Postgres adapters
* typed service boundaries
* bounded analytics behavior
* deterministic AI-assisted analytics
* operational workflow semantics

DO NOT:

* introduce ORM anti-patterns
* introduce raw unsafe SQL
* introduce hidden persistence layers
* introduce background-system sprawl
* introduce speculative service abstractions
* introduce microservice decomposition

---

# OBSERVABILITY RULES

Observability is part of the platform design.

Preserve:

* Prometheus metrics
* Grafana compatibility
* OpenTelemetry hooks
* readiness endpoints
* structured JSON logging
* correlation IDs
* operational telemetry semantics

DO NOT:

* redesign observability architecture
* introduce telemetry duplication
* remove operational metrics
* create hidden tracing systems

---

# CI/CD RULES

CI posture is now mature and must remain stable.

Preserve:

* GitHub Actions structure
* branch protection workflows
* Semgrep execution
* Gitleaks execution
* Dependabot integration
* Ruff/MyPy/Bandit workflows
* frontend lint/typecheck workflows

DO NOT:

* disable workflows casually
* weaken security enforcement
* introduce unstable CI redesigns
* add excessive workflow complexity

---

# TOKEN OPTIMIZATION RULES

ALWAYS optimize:

* token usage
* implementation scope
* execution time
* file churn
* dependency churn
* architectural movement

DO NOT:

* refactor scripts repeatedly
* rewrite stable systems unnecessarily
* revisit solved architecture repeatedly
* create broad cleanup tasks
* introduce speculative future-proofing

Prefer:

* larger cohesive implementation packs
* fewer repository passes
* minimal safe diffs
* additive incremental work

When possible:

* implement related changes together
* minimize repeated refactors
* minimize repeated validation passes

---

# TESTING POLICY

IMPORTANT:
Automated tests are NOT the default priority.

The primary validation path is manual validation by the repository owner.

DO NOT automatically run:

* full repository scans
* heavy CI-equivalent suites
* expensive integration tests
* unnecessary frontend rebuild loops
* long-running validations
* repeated validation cycles

ONLY run automated validation when:

* strictly necessary
* directly related to modified code
* required to verify a critical fix
* explicitly requested
* preventing a likely regression

Prefer:

* lightweight targeted validation
* py_compile
* focused import checks
* minimal lint/typecheck checks
* targeted execution-path validation

Always minimize:

* runtime cost
* token cost
* unnecessary validation repetition

---

# EXECUTION POLICY

Before implementation:

1. inspect existing modules
2. inspect existing contracts
3. inspect integration points
4. identify reusable infrastructure
5. identify minimal safe implementation path
6. identify operational/security risks

Implementation scope must remain:

* narrow
* incremental
* additive-first
* low-risk
* backwards-compatible whenever possible

DO NOT:

* touch unrelated files
* perform broad refactors
* introduce abstraction layers casually
* redesign stable systems
* solve speculative future problems

---

# DEPENDENCY RULES

Dependency churn is HIGH RISK.

DO NOT:

* upgrade ecosystems casually
* perform major framework upgrades without operational need
* introduce dependency instability
* blindly run upgrade tools with breaking changes

Especially avoid unnecessary churn involving:

* Next.js
* ESLint ecosystem
* Tailwind ecosystem
* observability tooling
* security tooling

Before dependency changes:

* identify operational need
* identify compatibility risk
* identify CI impact
* identify frontend/runtime risk

Prefer:

* minimal compatible upgrades
* stable ecosystem versions
* targeted security fixes

---

# README / DOCUMENTATION RULES

Documentation should remain:

* professional
* concise
* technically serious
* operationally realistic
* recruiter-friendly

Avoid:

* marketing-heavy wording
* fake-enterprise claims
* excessive verbosity
* tutorial-style sprawl
* architecture essays

README goals:

* fast evaluator understanding
* operational clarity
* realistic architecture communication
* strong public GitHub presentation

---

# HALLUCINATION PREVENTION

DO NOT:

* invent files
* invent APIs
* invent registries
* invent integrations
* assume architecture
* fabricate workflows
* assume runtime behavior

If uncertainty exists:

1. inspect repository first
2. inspect implementation first
3. inspect existing patterns first
4. request clarification instead of guessing

---

# COMMUNICATION STYLE

Be:

* concise
* technical
* incremental
* practical
* operationally grounded

Avoid:

* speculative recommendations
* unnecessary explanations
* fake-enterprise language
* excessive architectural theory

---

# IMPLEMENTATION TEMPLATE

Task:
[INSERT TASK]

Requirements:

* additive-first
* minimal code changes
* preserve contracts
* preserve observability
* preserve tenant isolation
* preserve auditability
* preserve deterministic behavior

Constraints:

* avoid broad refactors
* avoid touching unrelated systems
* avoid unnecessary dependency changes
* avoid frontend inflation
* avoid architecture redesign

Before coding:

* inspect repository first
* inspect integration points first
* inspect existing patterns first

After implementation:

1. summarize modified files
2. summarize integration points
3. summarize validations executed
4. summarize architectural safety
5. summarize operational/security impact

---

# SAFE ANALYSIS TEMPLATE

Do NOT implement yet.

First:

* inspect repository
* inspect architecture
* inspect integration points
* inspect workflows
* inspect contracts
* inspect security boundaries

Then:

1. identify safest integration point
2. identify reusable infrastructure
3. identify minimal implementation strategy
4. identify operational risks
5. identify security risks
6. identify architectural drift risks

Avoid speculative redesigns.

---

# DEBUG TEMPLATE

Perform controlled debugging only.

Rules:

* identify root cause first
* preserve architecture
* preserve deterministic behavior
* preserve security posture
* apply smallest safe fix

Process:

1. identify failing component
2. trace execution path
3. identify minimal root cause
4. apply smallest safe fix
5. run lightweight validation only if necessary

---

# FINAL REVIEW TEMPLATE

Before finalizing, verify:

* architecture preserved
* modular-monolith preserved
* no duplicated systems introduced
* no hidden orchestration introduced
* no unnecessary abstractions introduced
* no CI/security regressions introduced
* no tenant-isolation regressions introduced
* no operational drift introduced
* no unnecessary dependency churn introduced

Then provide:

1. concise summary
2. modified files
3. integration points
4. validations executed
5. operational/security impact
6. remaining risks
7. safest next incremental step

---

# FINAL RULE

Helix Sentinel is already advanced.

The primary risks are now:

* unnecessary complexity
* dependency instability
* architectural drift
* overengineering
* operational inconsistency
* frontend ecosystem churn

Always prioritize:

* simplicity
* modularity
* stability
* maintainability
* auditability
* security
* operational realism
* low operational risk
* token efficiency
