# Architecture check (opd-6289 slice1)

`arch_check.py` is the protected static check behind the required `architecture-check` status. It rejects, in the
iPad app source (`Frame/`) and in the packages the app links, direct hardware, networking, durable persistence and
application-owned logging sinks, plus the escape routes around them (subprocess, dynamic code, FFI), unless the
code is in `Packages/BaxterMiddlewareKernel`. Ordinary rendering, layout and computation pass.

* Candidate source is DATA. The lexer (`swift_lex.py`) drops comments and string text but keeps code inside
  string interpolations; nothing is imported, built or run.
* `policy/ipad-app.policy.json` is the boundary: zones, forbidden symbols/sequences per category with the supported
  route in each message, approved/kernel-only package products (`project.yml`), protected paths, and
  `allowed_sites` (exact file + rule + match, never a count).
* The policy, the checker, the workflow and CODEOWNERS are protected paths: a change to any of them fails the check
  and has to be approved and published by the owner (Todd, `tlavigne974os`), not by the change that needs it.
* Run it locally: `python3 -I tools/architecture-policy/arch_check.py --repo-root . --policy tools/architecture-policy/policy/ipad-app.policy.json`
* Tests: `python3 -I -m unittest discover -s tools/architecture-policy/tests`

Installed and required (verified live 2026-11-04, opd-1000707 U-16): `.github/workflows/architecture-check.yml` runs on
`pull_request_target` from the BASE branch; `.github/CODEOWNERS` assigns this directory, the workflow and CODEOWNERS to
the owner; the repository ruleset `main-guard` (id 25759281, enforcement active, no bypass actors) requires the
`architecture-check` status and code-owner review on the default branch. `ci/` keeps the staged originals. The separate `shepherd-architecture-policy` repository holds the owner-published policy release; this directory is
the working copy, and the owner re-publishes it when the protected files change.
