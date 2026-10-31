# State model and public interface

## PolicySet

Policies are immutable after creation.

```text
id            sequential integer
owner         creator address (provenance, not an admin key)
name          <= 100 characters
description   <= 1000 characters
invariants    ordered list, 1..8 entries, each <= 500 characters
policy_hash   SHA-256 of canonical invariant JSON
created_at    consensus-pinned transaction timestamp
```

No function edits or deletes a policy. A revised policy is a new record and a
new hash, preserving the exact rule set under which older audits were judged.

## EvidenceManifest

The caller supplies one to five GitHub file URLs and a full 40-character SHA.
The contract validates every URL before the nondeterministic block.

```text
manifest_hash = sha256(canonical({commit_sha, ordered files[url,path]}))
dedupe_key    = policy_id + ":" + manifest_hash
```

Ordering is intentional: it gives `file_index` a stable meaning in citations.

## AuditRecord

```text
id, policy_id, policy_hash
manifest_hash, commit_sha, files
requester
outcome: VERIFIED | VIOLATION | INCONCLUSIVE
reports[]
summary
created_at
```

Records are append-only. The same policy/manifest pair can be audited once;
another policy can audit the same source, and a later commit naturally creates
a different manifest hash.

## Transitions

```text
create_policy -> immutable PolicySet

valid unique manifest
      |
      v
custom GenLayer consensus
      |
      +-- disagreement / transaction failure -> no state change
      |
      +-- accepted -> append AuditRecord + set dedupe index
```

## API details

### `create_policy(name, description, invariants_json)`

Anyone may publish a policy. The caller is recorded as provenance but receives
no mutation or deletion authority.

### `audit(policy_id, manifest_json, commit_sha)`

Anyone may request an audit. Preconditions and manifest binding are checked
before any web or LLM call. Returns the new audit id after consensus.

### Views

Count getters allow deterministic enumeration. Record getters return complete
JSON-compatible objects. `find_audit` lets an integrator resolve a known
policy/manifest hash without scanning the ledger.
