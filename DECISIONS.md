# Engineering decisions

This log records why InvariantLens uses its current shape. Network-specific
findings will be appended after every live run rather than rewritten into a
clean retrospective.

## D-001 — One flagship primitive, not a catalog

The contribution optimizes for depth: a single reusable protocol with an
explicit threat model, adversarial tests, and live evidence. Breadth without
independent deployment evidence would weaken the submission.

## D-002 — Custom asymmetric consensus

Decision: use `gl.vm.run_nondet_unsafe` with a proof-producing leader and an
auditing validator.

Reason: comparative generation can establish that two models reached similar
answers, but it does not force either answer to expose a checkable proof. The
custom validator combines deterministic quote/span checks with semantic audit.

## D-003 — Immutable GitHub files only

Decision: reject repository pages, PRs, releases, branch refs, query strings,
and fragments. Rebuild every fetch through the Contents API using the submitted
SHA.

Reason: the audit must remain reproducible after branches and default refs move.

## D-004 — UNKNOWN is first-class

Decision: malformed leader output, weak coverage, missing evidence, and
external errors become all-UNKNOWN reports. Any UNKNOWN prevents VERIFIED.

Reason: forcing a binary decision turns uncertainty into false confidence.

## D-005 — Overall outcome is deterministic

Decision: models produce only per-invariant statuses. Contract code derives
VERIFIED, VIOLATION, or INCONCLUSIVE.

Reason: an LLM must not be able to return VERIFIED while one invariant is FAIL
or UNKNOWN.

## D-006 — Append-only, content-addressed records

Decision: policies and audits cannot be edited. Policy and manifest hashes bind
each result to exact rules and evidence. Exact duplicates are rejected.

Reason: attestations are useful only when downstream consumers can know which
rules and source produced them.

## D-007 — Local mocks are necessary but insufficient

The 28-test local suite exercises deterministic logic and the validator
boundary. It does not prove runner compatibility, model convergence, GitHub
availability from validators, or network finalization. Those claims remain
explicitly pending in `docs/DEPLOYMENT-EVIDENCE.md` until live transactions
exist.
