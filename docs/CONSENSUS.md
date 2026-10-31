# Consensus protocol

## Design claim

The consensus object is not free-form prose. It is a proof-carrying report:
bounded statuses, exact citations, an explicit counterexample attempt, and an
integer coverage score. Consensus must establish both structural integrity and
semantic support.

## Leader phase

The leader receives only plain local copies of the immutable policy and
manifest. Inside the nondeterministic block it:

1. Rebuilds each GitHub Contents API URL with `?ref=<submitted_sha>`.
2. Requires HTTP 200, a `file` response, base64 content, and a canonical
   `html_url` whose ref and path match the manifest.
3. Enforces per-file and total byte limits.
4. Numbers every source line.
5. Prompts for one ordered report per invariant.
6. Normalizes every field and verifies quoted text against the claimed span.

The leader cannot return `VERIFIED`; it returns only per-invariant reports.

## Validator phase

InvariantLens uses `gl.vm.run_nondet_unsafe` because the validator has two
different jobs:

1. Independently fetch the exact same commit-pinned files.
2. Programmatically validate the candidate schema and citations.
3. Audit the semantic report with an LLM using the complete bounded bundle.
4. Require an exact status vector and a positive audit judgment.

An exception or malformed validator answer is disagreement. No audit record is
written when consensus fails.

## Why not plain comparative consensus?

Two independent reports can agree while sharing the same unsupported
assumption. The asymmetric protocol makes the leader expose a proof surface and
asks validators to attack that specific proof. It also lets validators reject
fabricated line spans deterministically before spending judgment on semantics.

## Consensus invariants

- Nondeterministic functions never read or write contract storage.
- Every validator fetch uses the submitted SHA, never a branch.
- `PASS` requires at least one citation and `coverage_milli >= 650`.
- `FAIL` requires at least one citation.
- A citation must quote text inside its declared line range.
- Validator `status_vector` must exactly match the candidate report.
- Model-provided overall outcomes are ignored because none are requested.
- Any `FAIL` deterministically dominates the overall result.
- Any `UNKNOWN` prevents `VERIFIED`.

## External failures

When both leader and validator cannot retrieve the evidence, an all-`UNKNOWN`
report can finalize as `INCONCLUSIVE`. If the leader fails but a validator can
retrieve the source, the validator audits the candidate and may disagree. No
external error path can produce `PASS` or `VERIFIED`.

## Output schema

```json
{
  "reports": [
    {
      "invariant_index": 0,
      "status": "PASS",
      "citations": [
        {
          "file_index": 0,
          "start_line": 12,
          "end_line": 14,
          "quote": "assert sender == owner"
        }
      ],
      "reason": "The privileged path checks the transaction sender.",
      "counterexample": "Searched the remaining privileged entry points.",
      "coverage_milli": 900
    }
  ],
  "summary": "All registered invariants are supported by the bounded manifest."
}
```
