# InvariantLens

**Proof-carrying semantic compliance for immutable source code.**

Ordinary code scanners are excellent when a rule can be reduced to syntax. They
are much weaker when the rule is about meaning:

- "Every privileged write requires sender authorization."
- "An HTTP failure can never become an approval."
- "A payout cannot exceed the credit already recorded for its recipient."

InvariantLens turns those policies into reusable GenLayer attestations. A
leader analyzes a bounded set of commit-pinned source files and must return a
structured verdict with exact citations, coverage, and an attempted
counterexample. Validators independently fetch the same immutable files,
verify the citations in code, and audit whether the cited evidence actually
supports the conclusion. Only the consensus-agreed report reaches storage.

> Agreement is not enough. A useful AI verdict must carry a proof another
> validator can audit.

## Why this is an Intelligent Contract primitive

InvariantLens is not an application and not a thin "AI decides" wrapper. It is
a standalone semantic CI gate that other contracts, DAOs, bounty systems,
grant programs, release pipelines, and agent registries can wrap.

Its consensus design is load-bearing:

1. **Leader produces, validators audit.** The expensive work is a
   proof-carrying report; validators verify that report rather than merely
   generating another paragraph.
2. **Evidence is immutable.** Every accepted URL embeds the same submitted
   40-character Git commit SHA. Fetches are rebuilt through GitHub's Contents
   API with `?ref=<sha>`.
3. **Citations are checked twice.** Code verifies that every quote exists at
   the claimed file and line span; validator LLMs judge whether it supports the
   semantic conclusion.
4. **Refusal is a result.** Missing evidence, malformed output, weak coverage,
   or GitHub errors become `INCONCLUSIVE`, never `VERIFIED`.
5. **State stays exact.** Policies are immutable, audits are append-only,
   manifests are content-addressed, duplicate work is rejected, and the final
   outcome is derived deterministically from per-invariant statuses.

## Consensus flow

```text
policy + SHA-bound manifest
            |
            v
 leader fetches every file at ?ref=<sha>
            |
            v
 report: PASS | FAIL | UNKNOWN
         + exact line citations
         + coverage score
         + attempted counterexample
            |
            v
 validators independently refetch the same commit
            |
            +-- code: do quotes exist at those line spans?
            |
            +-- LLM: do citations support the status and coverage?
            |
            v
 consensus result -> deterministic outcome -> append-only record
```

The overall result is never accepted from an LLM:

| Per-invariant results | Stored outcome |
|---|---|
| every status is `PASS` | `VERIFIED` |
| any status is `FAIL` | `VIOLATION` |
| otherwise | `INCONCLUSIVE` |

## Repository map

```text
contracts/invariant_lens.py       deployable single-file GenLayer contract
contracts/contract-metadata/      generated and checked ABI schema
tests/test_invariant_lens.py      deterministic + consensus-boundary tests
docs/CONSENSUS.md                 leader/validator protocol and invariants
docs/STATE-MODEL.md               state, hashes, transitions, public API
docs/THREAT-MODEL.md              attacker model, mitigations, residual risk
docs/REUSE-GUIDE.md               integration patterns for other builders
docs/DEPLOYMENT-EVIDENCE.md       Studionet deployment and live-run record
examples/security-policy.json     example reusable policy set
DECISIONS.md                      engineering decisions and live findings
```

## Public API

Writes:

```python
create_policy(name: str, description: str, invariants_json: str) -> int
audit(policy_id: int, manifest_json: str, commit_sha: str) -> int
```

Views:

```python
get_policy_count() -> int
get_audit_count() -> int
get_policy(policy_id: int) -> dict
get_audit(audit_id: int) -> dict
find_audit(policy_id: int, manifest_hash: str) -> int
```

`manifest_json` is an array of one to five immutable GitHub file URLs. All URLs
must contain the same full SHA passed in `commit_sha`:

```json
[
  "https://github.com/org/repo/blob/0123456789abcdef0123456789abcdef01234567/contracts/main.py",
  "https://raw.githubusercontent.com/org/repo/0123456789abcdef0123456789abcdef01234567/tests/test_main.py"
]
```

## Run the tests

The local suite uses a minimal GenLayer runtime stub so it can exercise the
contract's deterministic state and custom validator boundary without a live
network:

```bash
./scripts/check.sh
```

Current suite: **28 tests**. It covers the happy paths plus mutable refs, SHA
mismatches, GitHub errors, forged citations, malformed model output, validator
disagreement, duplicate audits, access-independent requester tracking, size
limits, and deterministic outcome derivation.

The check script also runs the official `genvm-lint check` command and compares
the generated ABI schema with the checked-in schema.

Official `gltest` integration tests and finalized Studionet transactions will
be recorded in `docs/DEPLOYMENT-EVIDENCE.md` before submission.

## Hard boundaries

- No funds, tokens, or upgrades.
- No repository-wide claim: only the submitted bounded manifest is audited.
- No secret state: all policies, evidence URLs, and reports are public.
- A `VERIFIED` result means the submitted files support the registered
  invariants under validator consensus; it is not a complete security audit.
- GitHub availability remains an external dependency. Failure is safe but can
  reduce liveness.

See [the threat model](docs/THREAT-MODEL.md) for the full residual-risk list.

## License

MIT
