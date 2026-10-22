# shepherd-architecture-policy

The protected architecture check for Baxter apps (owner: tlavigne974os). Consumer repositories run a PINNED RELEASE of this repository from a `pull_request_target` workflow; the candidate source is data only.

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
* Run it locally: `python3 -I arch_check.py --repo-root . --policy policy/ipad-app.policy.json`
* Tests: `python3 -I -m unittest discover -s tests`

Staged for the owner (deliberately NOT under `.github/`, so nothing activates yet): `ci/architecture-check.workflow.yml` (install as `.github/workflows/architecture-check.yml`, runs on `pull_request_target`, posts the `architecture-check` status on the candidate head) and `ci/CODEOWNERS.proposed`. They go live together with the owner actions, once the tree is clean, so no other seat's PR turns red in the meantime.

Status: the check, its tests and the workflow exist in this repository. They are NOT yet a protected, required
status: that needs the owner actions listed on opd-6289 (a separate `shepherd-architecture-policy` repository,
branch protection with the required `architecture-check` context, code-owner review on the protected paths).
