# Tamper-evident audit log (Milestone 8)

Implementation: `src/cryptography/audit_log.py`. Tests: `tests/test_audit_log.py`. Records are stored in the SQLite table
`audit_log` of the backend database (`experiments/graphsentinel.sqlite`, git-ignored).

## Construction
| field | content |
|---|---|
| `event_id` | consecutive integer starting at 1 |
| `timestamp` | ISO-8601 UTC with microseconds |
| `event_type` | e.g. `server_start`, `detection` |
| `details` | JSON object, never raw traffic (detections log file SHA-256, counts, model) |
| `prev_hash` | H<sub>i-1</sub> (hex); H<sub>0</sub> = 64 zeros |
| `hash` | H<sub>i</sub> = SHA-256( bytes(H<sub>i-1</sub>) ‖ CanonicalRecord<sub>i</sub> ) |
| `hmac` | HMAC-SHA256( key, bytes(H<sub>i</sub>) ) |

CanonicalRecord<sub>i</sub> is the UTF-8 encoding of `json.dumps({event_id, timestamp, event_type, details},
sort_keys=True, separators=(",", ":"), ensure_ascii=False)`. Key order and whitespace therefore cannot change a hash.
Appends run inside `BEGIN IMMEDIATE`, so concurrent writers cannot fork the chain.

## Key management
- **Where the key comes from:** the key is read from `GRAPHSENTINEL_HMAC_KEY` (hex) or from the file named by
  `GRAPHSENTINEL_HMAC_KEY_FILE` (default `keys/hmac.key`). If neither exists, 32 random bytes are written to a new key
  file, created exclusively.
- **Where it never goes:** `keys/` and `.env` are git-ignored. The key is never written to source code, the database
  or the logs.
- **Minimum length:** keys shorter than 32 bytes are rejected.

## Verification (`AuditLog.verify`, `GET /api/audit/verify`)
Verification checks four things for every record:
- the sequence continuity
- `prev_hash` linkage
- recomputation of H<sub>i</sub>
- the HMAC, using a constant-time comparison

It reports every failure with the `event_id` where it occurs. Pass a trusted checkpoint `{event_id, hash}` to also
detect truncation.

Run the demo with `python -m src.cryptography.audit_log demo`. It is also available as `POST /api/audit/demo` and uses
a temporary log.

| scenario | detected? |
|---|---|
| record `details` edited | yes: hash mismatch |
| attacker re-computes the SHA-256 chain without the key | yes: HMAC invalid from the edited record on |
| newest record deleted, no checkpoint | **no** (limitation, shown deliberately) |
| newest record deleted, verifier holds checkpoint | yes: checkpoint mismatch |
| record in the middle deleted | yes: sequence gap / prev_hash mismatch |

## Limitations
1. **SHA-256 alone does not authenticate.** Anyone can recompute a hash chain. Only the HMAC binds records to the key
   holder.
2. **Truncation needs a checkpoint.** Whoever controls the storage can delete the newest records undetected unless the
   verifier holds a trusted checkpoint of the head hash. The checkpoint must be kept somewhere that storage owner cannot
   modify, for example printed in a report, sent to another party or kept in a WORM store.
3. **The HMAC key lives on the same host as the log.** An attacker who compromises that host can read the key and forge
   a fully valid chain. Real deployments need key separation (HSM/KMS, or a remote signing or witness service) and
   periodic external anchoring of the head hash.
4. **No key rotation is implemented.** Rotating would require recording key ids per record.
5. **Timestamps come from the local clock.** They are not trusted time.
