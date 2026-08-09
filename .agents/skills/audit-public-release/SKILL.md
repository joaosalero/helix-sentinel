---
name: audit-public-release
description: Audit a Helix Sentinel GitHub-public or release scope for private data, secrets, local infrastructure references, and standalone readiness.
---

Use this skill before a public GitHub publication, release, demo handoff, or
standalone distribution review.

1. Define the proposed publication scope from the Git diff, staged state, and
   relevant untracked files; do not stage, commit, publish, or send anything.
2. Inspect for secrets, credentials, tokens, personal identifiers, local paths,
   internal endpoints, private AI configuration, sensitive samples, logs,
   generated metadata, private dependencies, and relevant untracked artifacts.
3. Verify documentation and public configuration do not make private local AI
   infrastructure a requirement and that safe defaults remain in place.
4. Distinguish confirmed exposure from plausible release risk. Cite file paths and
   categories only; never print a suspected secret value.
5. Report release blockers, warnings, scope exclusions, standalone-readiness
   evidence, and the smallest safe remediation. Do not modify files without
   explicit implementation authorization.

Activate for: “prepare this repository for public release”, “audit this GitHub
scope”, or “check standalone readiness”. Do not activate for a normal local
development review with no publication intent.
