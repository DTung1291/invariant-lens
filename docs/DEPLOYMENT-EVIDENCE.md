# Studionet deployment evidence

Status: **deployed and end-to-end workflow finalized**.

## Immutable deployment

- Network: GenLayer Studionet
- Deployed contract:
  [`0xC336F8ad392B08c5a2527403dDBA4Fc819FB1666`](https://explorer-studio.genlayer.com/address/0xC336F8ad392B08c5a2527403dDBA4Fc819FB1666)
- Deployment transaction:
  [`0x19b95469fc2945cd7892e1bd91833b803f0d80ad6b39a9e8b0a3cafce3faaa0c`](https://explorer-studio.genlayer.com/tx/0x19b95469fc2945cd7892e1bd91833b803f0d80ad6b39a9e8b0a3cafce3faaa0c)
- Deployed source commit:
  [`215e4d52aa0138306e57557544d87271e3259a1a`](https://github.com/DTung1291/invariant-lens/tree/215e4d52aa0138306e57557544d87271e3259a1a)

The contract source at that commit is the source deployed at the address above.
Later documentation-only commits do not change the deployed contract.

## Finalized workflow

Policy 1, `Immutable Evidence Binding`, requires the submitted README to state
that every accepted evidence URL embeds the same submitted full Git commit SHA.

- Policy transaction:
  [`0x0d25733881a6c0ddc8d6d42580d8c96a63c5f0fed00db26338c343658a3d4b00`](https://explorer-studio.genlayer.com/tx/0x0d25733881a6c0ddc8d6d42580d8c96a63c5f0fed00db26338c343658a3d4b00)
- Audit transaction:
  [`0x3c539f75dd0f7342469218e305017ec81f4b181bb729400e8bd3051a528a3a76`](https://explorer-studio.genlayer.com/tx/0x3c539f75dd0f7342469218e305017ec81f4b181bb729400e8bd3051a528a3a76)
- Manifest:
  [`README.md` at the deployed source commit](https://github.com/DTung1291/invariant-lens/blob/215e4d52aa0138306e57557544d87271e3259a1a/README.md)
- Submitted `commit_sha`: `215e4d52aa0138306e57557544d87271e3259a1a`
- Final transaction status: `FINALIZED`
- `get_policy_count()`: `1`
- `get_audit_count()`: `1`

The audit initially caused one leader rotation, then validator consensus was
reached and the transaction finalized. `get_audit(1)` returned:

```json
{
  "id": 1,
  "policy_id": 1,
  "commit_sha": "215e4d52aa0138306e57557544d87271e3259a1a",
  "manifest_hash": "5e08f4ce2f151b6ebc10954cc12ad7b6082dbf75895531dbe99cb5151e85e317",
  "policy_hash": "e182f73c2b4fad58f80769a543935e7a6d0e874f122eb472345ed732e3f3bf35",
  "outcome": "VERIFIED",
  "reports": [
    {
      "invariant_index": 0,
      "status": "PASS",
      "coverage_milli": 1000,
      "citations": [
        { "file_index": 0, "start_line": 33, "end_line": 35 },
        { "file_index": 0, "start_line": 112, "end_line": 113 }
      ]
    }
  ]
}
```

The complete report stored on-chain also contains the exact quoted source
spans, the leader's counterexample attempt, its reasoning, and the audit
summary. The result demonstrates the full primitive: immutable fetch,
proof-carrying leader report, independent validator audit, leader rotation,
consensus, deterministic outcome derivation, and append-only storage.

This is a positive conformance example. `VIOLATION` and `INCONCLUSIVE` paths
are covered by deterministic and consensus-boundary tests; no additional live
transaction is represented here as having been run.
