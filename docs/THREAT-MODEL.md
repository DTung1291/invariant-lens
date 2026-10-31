# Threat model

## Protected properties

1. Mutable web content cannot be represented as immutable evidence.
2. A submitted SHA controls every file fetched by validators.
3. HTTP errors, malformed API responses, or mismatched refs cannot verify.
4. Fabricated citations cannot survive deterministic span validation.
5. LLM output cannot directly select the stored overall outcome.
6. Consensus disagreement cannot partially write an audit.
7. Historical policies and audit reports cannot be edited or deleted.

## Attacker capabilities

The requester controls policy text, manifest URLs, repository contents, source
comments, filenames, and commit selection. Repository content may contain
prompt injection. A GitHub/API response may be missing, malformed, oversized,
or inconsistent between nodes. A leader model may hallucinate citations or
overstate coverage. A validator model may disagree or return malformed JSON.

## Mitigations

| Threat | Mitigation |
|---|---|
| Branch or mutable URL | Only `blob/<40-char SHA>/...` and raw SHA URLs are accepted |
| Submitted SHA ignored | Every API URL is reconstructed with `?ref=<sha>` |
| API returns another ref/path | Canonical `html_url` ref and path must match |
| HTTP error treated as content | Status must equal 200 before decoding |
| Prompt injection in source | Source is delimited and repeatedly labeled untrusted data |
| Fabricated citation | Quote must exist inside exact file/line span |
| Unsupported PASS | Citation required, coverage floor, semantic validator audit |
| Malformed leader output | Normalized to an all-UNKNOWN report |
| Malformed validator output | Validator disagrees; transaction writes no state |
| Duplicate audit spam | Content-addressed dedupe key per policy and manifest |
| Resource exhaustion | Caps on policies, files, response bytes, total bytes, and output fields |

## Residual risks

- Multiple validator models can share the same blind spot.
- Line citations demonstrate local evidence, not repository-wide completeness.
- A malicious policy can ask an ill-defined question; `UNKNOWN` is the intended
  safe outcome but models may still overestimate coverage.
- GitHub is a centralized availability dependency. Immutable refs protect
  integrity, not liveness.
- `coverage_milli` is a consensus-audited judgment, not a formal proof metric.
- A verified bounded manifest is not equivalent to a complete security audit.

## Operational guidance

High-stakes consumers should require policies written by a known publisher,
include all security-relevant entry points in the manifest, and treat
`INCONCLUSIVE` as a hard stop. They should never interpret missing audit records
or failed consensus as approval.
