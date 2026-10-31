# Reuse guide

InvariantLens is intended to sit behind another workflow rather than become a
finished product itself.

## Pattern 1: DAO upgrade gate

Register invariants covering admin authorization, upgrade delay, and fund
movement. Audit the exact implementation files at the proposed release SHA.
The DAO's off-chain proposal tooling proceeds only when the stored outcome is
`VERIFIED` and the `policy_hash` matches the approved policy version.

## Pattern 2: Grant or bounty acceptance

Publish delivery invariants before work starts. The submitter provides a small,
reviewable manifest at a commit SHA. A grant contract or coordinator can use
the audit id as a reusable attestation instead of repeating the AI judgment.

## Pattern 3: Agent tool policy

Audit an agent's tool router against invariants such as confirmation before
external writes, secret redaction, and fail-closed network handling. Pinning
the source SHA prevents a passing audit from silently following later code.

## Integration checklist

- Store or independently know the expected `policy_hash`.
- Recompute the manifest hash using the exact ordered URL/path list.
- Require `VERIFIED`; never treat no record, transaction failure, or
  `INCONCLUSIVE` as success.
- Display the commit SHA and cited line ranges to human reviewers.
- Create a new audit for every release commit.
- Keep manifests bounded but complete for the invariant being claimed.

## Example policy

See `examples/security-policy.json`. Submit its `invariants` array to
`create_policy`, then pass the exact relevant source files to `audit`.
