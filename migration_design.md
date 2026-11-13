# Migration design: hybrid classical + ML-DSA at the API layer

How the RPC and API surface migrates to post-quantum signatures
without breaking existing clients, and what it costs. All sizes are
from NIST FIPS 204 Table 2 (exact standard values); verification
times on node hardware are unmeasured and listed as an open question.

## 1. What must change, and what must not

**Must change** — the four signing entry points, because every
signature they produce is recorded on the public ledger forever and
becomes harvestable the moment it is submitted:

| Method | Change |
|---|---|
| `sign` | Accept a `key_type` of `ml-dsa-65` (and later `ml-dsa-44` / `ml-dsa-87`); produce a hybrid signature: classical (Ed25519 or secp256k1) **plus** ML-DSA-65 over the same signing hash. Return both signatures in `tx_json` / `tx_blob`. |
| `sign_for` | Same, per signer in a multi-signed transaction. |
| `channel_authorize` | Accept an ML-DSA key; return a hybrid claim signature (classical + ML-DSA-65 over the `CLM` message). The on-ledger claim verification (`PayChan.cpp:469-486`) must accept the hybrid form. |
| `submit` | Accept and relay hybrid-signed transactions. The deprecated server-side signing path must be removed, not migrated: a public node must never sign. |

**Must not change** — the read surface (`account_tx`, `tx`,
`ledger`, `ledger_data`, `ledger_entry`, `transaction_entry`,
`tx_history`, `manifest`, `server_info`, `server_state`). It only
relays what the ledger records. Its clients must be *able to verify*
ML-DSA signatures (library support), but the methods themselves need
no change.

**Must be hardened regardless of quantum timelines** — the ADMIN gate
and the signing switch:

- Audit every port's `admin` nets and `admin_user` /
  `admin_password` per deployment. The gate held on the probed
  endpoint (23/23 HTTP 403), but it is configuration, not
  cryptography; a single misconfigured port exposes
  `wallet_propose` / `validation_create` secret generation and
  `stop` / `ledger_accept` / `connect` node control to any caller.
- Keep signing disabled (`canSign() == false`) on every public node.
  The probed node already does this — `sign`, `sign_for`,
  `channel_authorize` and the `submit` signing path all return
  `notSupported`. Treat any public node with signing enabled as a
  misconfiguration to fix immediately.
- Put the ADMIN port on loopback (or a private network) and the
  public port on a separate listener with no `admin` nets.

## 2. Sizes and costs (FIPS 204, exact)

| Scheme | Public key | Signature | Signature vs Ed25519 (64 B) |
|---|---|---|---|
| Ed25519 | 32 B | 64 B | 1× |
| secp256k1 (DER) | 33 B | 70–72 B | ~1.1× |
| ML-DSA-44 | 1,312 B | 2,420 B | 37.8× |
| ML-DSA-65 | 1,952 B | 3,309 B | 51.7× |
| ML-DSA-87 | 2,592 B | 4,627 B | 72.3× |

Recommended parameter set: **ML-DSA-65** (NIST security category 3,
matching the 192-bit classical strength of the secp256k1 / Ed25519
usage it replaces; ML-DSA-44 is category 1, ML-DSA-87 is category 5
and 40% larger per signature).

Per-call cost of hybrid signing:

- One hybrid-signed transaction carries one extra signature:
  **+3,309 B** (ML-DSA-65) plus the 1,952 B public key on first use.
  At the measured testnet rate (~0.29 transactions per ledger, companion
  historical-ledger pack) that is ~950 B per ledger on average —
  negligible. At 1,000 transactions per ledger it is ~3.3 MB per
  ledger of extra signature data.
- One hybrid payment-channel claim carries one extra signature:
  **+3,309 B** per claim (claims are off-ledger, so no ledger bloat).
- `wallet_propose` / `validation_create` generating an ML-DSA keypair
  returns an extra 1,952 B public key and stores a 4,032 B ML-DSA-65
  secret key (FIPS 204 Table 2) instead of a 32-byte seed-derived
  secret. Key storage per identity grows substantially; key generation is
  a rare operation.
- Verification throughput on node hardware is **unmeasured** (open
  question Q3). Published estimates used by the companion consensus
  migration pack put ML-DSA-65 verification in the same order of
  magnitude as classical verification per signature; the binding
  constraint at the API layer is response size, not CPU.

## 3. Phased plan

Phases are sequenced with the consensus migration pack's activation
amendment; the API phases below assume that amendment exists and
follow its numbering where they overlap.

- **Phase 0 — Harden now (no protocol change).** Audit ADMIN port
  configuration on every deployment; confirm signing is disabled on
  all public nodes; document the ADMIN gate per port. Cost: audit
  time only. Rollback: configuration change.
- **Phase 1 — Library and key types.** Add ML-DSA-65 key generation
  to `wallet_propose` / `validation_create` (new `key_type`
  values); add ML-DSA-65 verification to the transaction and claim
  verification paths. No signing yet; the node can verify hybrid
  transactions submitted by upgraded clients. Cost: library
  integration + tests. Rollback: remove the key types.
- **Phase 2 — Hybrid signing at the API.** `sign`, `sign_for` and
  `channel_authorize` produce dual signatures; `submit` relays
  hybrid transactions; remove the deprecated `submit` server-side
  signing path. Clients opt in per call (`key_type: ml-dsa-65`).
  Cost: +3,309 B per hybrid signature (Section 2). Rollback: stop
  producing ML-DSA signatures; classical signatures remain valid.
- **Phase 3 — Transport.** TLS 1.3 hybrid key exchange (ML-KEM-768:
  public key 1,184 B, ciphertext 1,088 B, FIPS 203 Table 2) for the
  HTTPS and WebSocket listeners, and TLS + authentication for gRPC
  (currently unauthenticated, `InsecureServerCredentials`). Blocked
  on the TLS stack: the pinned OpenSSL 1.1.1w has no ML-KEM; this
  needs OpenSSL 3.5 or later (companion peer-overlay pack). Cost:
  library upgrade + handshake bytes. Rollback: fall back to
  classical TLS 1.3.
- **Phase 4 — Activation.** Amendment enabling hybrid signatures as
  the required form for new transactions; grace period in which
  classical-only transactions are still accepted. After activation
  there is **no protocol rollback**: the amendment mechanism has no
  disable path for enabled amendments (companion consensus migration
  pack). Recovery after activation is forward-only.
- **Phase 5 — Classical deprecation.** Reject classical-only
  signatures for new transactions; keep verification of historical
  classical signatures forever (history cannot be re-signed — see
  the companion historical-ledger pack: full re-signing is not
  feasible). The read surface keeps returning historical classical
  signatures indefinitely.

## 4. Key rotation

- Account keys: rotation is a new `wallet_propose` + a transaction
  moving funds / updating the regular key. Old keys stay valid for
  historical signatures; the account's *current* key is what matters
  for new transactions. Rotation must happen **before** a quantum
  adversary exists — a key exposed in any past transaction is
  harvestable from the ledger (see `exposure_analysis.md` Section 1).
- Validator keys: rotation is a new manifest (`manifest` method
  returns manifests; `validation_create` generates the key). The
  probed node validates with its master key directly (no separate
  ephemeral key) — rotation there means a new master key and a new
  manifest, published through the validator-list process.
- API keys: there are none — the JSON-RPC surface has no API keys.
  Access control is the ADMIN gate (Section 1) and the signing
  switch. Do not add API keys as a substitute for either.

## 5. What stays safe without any migration

- The read surface (Section 1 of `exposure_analysis.md`): it relays
  public ledger data and needs no change.
- `random`: returns CSPRNG output, not key material.
- `channel_verify`: verifies a supplied signature; it cannot forge
  one, and a hybrid signature verifies under the same call once the
  verifier supports ML-DSA.
- Historical classical signatures: they remain verifiable forever;
  they cannot be removed from history, and they do not need to be.

## 6. Open questions

- **Q1.** Which ML-DSA parameter set should be the default —
  ML-DSA-65 (recommended here) or ML-DSA-44 for smaller signatures?
  Decided by the activation amendment, not by this pack.
- **Q2.** Should `sign` produce dual signatures in one call, or
  should clients call it twice (once per scheme)? One call is
  simpler; two calls keep the response shape unchanged.
- **Q3.** ML-DSA-65 verification throughput on node hardware
  (signatures per second per core) — unmeasured; needed to size the
  `submit` rate limits after activation.
- **Q4.** Maximum transaction blob size for hybrid transactions:
  does the current `tx_blob` limit accommodate a 3,309 B signature
  plus a 1,952 B public key, and should the limit rise?
- **Q5.** Hybrid payment-channel claim format: two signatures in one
  claim, or two claims? The claim verification path
  (`PayChan.cpp:469-486`) must be specified before Phase 2.
- **Q6.** gRPC authentication mechanism: mutual TLS or token-based?
  The gRPC server currently has none; the choice affects operators,
  not the protocol.
- **Q7.** Should the `validations` WebSocket stream carry hybrid
  validation signatures before or after the activation amendment?
  Streaming them early lets observers test verification; streaming
  them late keeps the stream classical-only until activation.
