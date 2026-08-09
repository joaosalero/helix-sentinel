---
name: plan-risk-based-validation
description: Create a risk-proportionate validation plan for a Helix Sentinel diff using existing Makefile and script commands.
---

Use this skill when a Helix Sentinel change needs a validation matrix before or
after implementation.

1. Inspect the diff and map each changed path to behavior, security, persistence,
   dependency, CI, frontend, documentation, or trust-boundary risk.
2. Select the smallest sufficient set from existing commands such as `make test`,
   `make lint`, `make format-check`, `make typecheck`, `make security`,
   `make frontend-lint`, `make frontend-typecheck`, `make check`,
   `make release-check`, and `scripts/check.sh`.
3. Start with focused checks. Expand for authentication, authorization, tenant
   isolation, persistence, migrations, security controls, dependencies, CI, or
   public/private-boundary changes.
4. Avoid repeating an already approved suite when the relevant state has not
   changed, but never omit validation required by risk.
5. Report proposed or executed commands, purpose, expected confidence, checks not
   selected, and residual risks. Do not modify files or claim execution unless it
   occurred.

Activate for: “what should I test for this diff?”, “plan validation”, or “choose
targeted checks”. Do not activate for an unrelated architecture or security review.
