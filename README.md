# Post-Quantum RPC and API Surface Security Assessment

Which PFTL API methods expose public keys, signatures, or signing
capability to an unauthenticated caller; which are gated to ADMIN;
and how the surface should migrate to post-quantum signatures.

**Canonical results page: `docs/index.html`.**

## Headline finding

The API surface splits cleanly in two. The **read surface** hands
out public keys and signatures to anyone who asks — 6 methods
returned a key or signature field in their live response — but that
needs no migration: it only relays what the public ledger already
records. The **signing surface** is 4 methods (`sign`, `sign_for`,
`channel_authorize`, and the deprecated `submit` signing path), all
reachable without authentication — and on the probed node all four
are closed by configuration (signing disabled), not by code. The
highest-severity API-specific risk is a misconfigured **ADMIN gate**:
it is the only thing between an unauthenticated caller and secret
generation (`wallet_propose`, `validation_create`) and node control
(`stop`, `ledger_accept`, `connect`). The gate held on the probed
endpoint — 23 of 23 ADMIN methods refused with HTTP 403 Forbidden —
but it is per-port configuration, not cryptography.

## Headline numbers (from `results/summary.json`)

- Methods inventoried: **74 JSON-RPC (51 USER, 23 ADMIN)** + 4 gRPC
  + 10 WebSocket streams. The embedded inventory was cross-checked
  against a fresh parse of the handler table
  (`tree_table_check.matches: true`).
- Probed live, unauthenticated, 2026-11-13T20:57:45Z from
  `https://rpc.testnet.postfiat.org/`: **32 success, 19 RPC error,
  23 HTTP 403 Forbidden, 0 transport errors.**
- ADMIN gate: **23 of 23 refused with HTTP 403 Forbidden.**
- Signing disabled on this node: `sign`, `sign_for`,
  `channel_authorize` and `submit` all return `notSupported` (75),
  "Signing is not supported by this server."
- Public keys / signatures observed live in 6 responses:
  `account_tx` (5 transactions, Ed25519 `SigningPubKey` +
  `TxnSignature`), `tx` / `transaction_entry` (Ed25519 key +
  signature), `manifest` (validator ephemeral + master key),
  `server_info` / `server_state` (node public key `n9K4Aom…`).
- Server: build 1.0.9, network_id 2025, validated ledger 8023087,
  complete_ledgers 7950054–8023087, 21 peers, validation quorum 17.
- Transport observed via the egress proxy: TLS 1.3,
  `TLS_AES_256_GCM_SHA384`, X25519. The origin server's own TLS is
  not observable from this machine (egress proxy re-signs the
  certificate).
- No secret material was returned by any probe (redaction count 0).
  No secret, seed or passphrase was ever sent.

## Migration verdict

Migrate the four signing entry points to hybrid classical + ML-DSA-65
signatures (+3,309 B per signature, FIPS 204) in phases, keep the
read surface unchanged, harden the ADMIN gate per deployment now,
and add TLS + authentication to gRPC (currently unauthenticated).
After the activation amendment there is no protocol rollback —
recovery is forward-only. See `migration_design.md`.

## Scanned tree

- Repository: postfiatd
- Commit: `0085a1ff885d6a446369cf73a4430f75af22be55`
  ("Merge pull request #50 from postfiatorg/hotfix/upstream-hardening-1.0.9")
- The harness records the tree's `HEAD` commit in
  `results/summary.json` (`tree_check`), so a wrong tree is
  detectable. The tree used at authoring time was a detached checkout
  at `0085a1ff`.

## Companion packs (same pinned tree)

- Historical ledger quantum-exposure audit (10 record classes; 142
  sampled transactions, all Ed25519 64-byte signatures; PQ
  checkpoints recommended): the probe account and transaction hash
  used here come from that pack's public sample.
- Consensus signature migration design (37 consensus-path call
  sites; ML-DSA-65 sizes; 5-phase migration; no rollback after
  activation): the phased plan in `migration_design.md` is sequenced
  with its activation amendment.
- Peer-overlay transport security assessment (cipher list
  `TLSv1.2:!CBC:!DSS:!PSK:!eNULL:!aNULL`; ML-KEM native in OpenSSL
  3.5): the transport findings here cite its TLS conclusions.

## Reproduce

Requirements: Python 3.8+ (standard library only), a checkout of the
pinned tree, `git` (only to record the tree commit), `sha256sum`.

```sh
# 1. Regenerate every derived output offline from the vendored sample
#    (no network access):
./run_all.sh

# 2. Verify the digest manifest:
./verify_digests.sh --check

# 3. Re-probe live instead (public read-only endpoint,
#    no credentials) — overwrites results/probe_raw.json and
#    all derived outputs with a new probe run:
python3 harness.py --live
./run_all.sh
```

`run_all.sh` runs `harness.py` in offline mode (regenerates
`results/summary.json`, `results/*.csv`, `results/summary.txt`,
`api_inventory.csv` from the vendored `results/probe_raw.json`),
then `build_derived.py` (regenerates `docs/index.html`), then
`verify_digests.sh` (rebuilds `SHA256SUMS`). The offline path is
deterministic: a fresh copy of the pack regenerates byte-identical
derived outputs. See `REPRODUCTION.md` for the fresh-environment
reproduction record and `results/run_log.txt` for the raw console log
of that run. Tool versions used at authoring time: Python 3.12.3,
git 2.43.0, GNU coreutils `sha256sum` (Ubuntu).

## Pack contents

| File | What it is |
|---|---|
| `docs/index.html` | Canonical results page |
| `harness.py` | Probe harness (live probe + offline regeneration) |
| `results/probe_raw.json` | Vendored raw probe responses (redacted, size-capped) |
| `results/fetch_log.json` | Per-request probe outcomes |
| `results/summary.json`, `results/summary.txt` | Aggregate measured results |
| `results/probe_results.csv` | One row per method (role, exposure, outcome, error) |
| `results/method_counts.csv` | Counts by outcome, error code, exposure class, role |
| `api_inventory.csv`, `api_inventory.md` | Method inventory with file:line evidence |
| `exposure_analysis.md` | Per-method quantum-exposure analysis |
| `migration_design.md` | Hybrid ML-DSA migration design, phased plan, costs |
| `sources.md` | Primary sources |
| `assumptions.md` | Assumptions and limits — read before citing numbers |
| `claim_evidence_index.md` | Every headline claim mapped to file, field and line |
| `run_all.sh`, `verify_digests.sh`, `SHA256SUMS` | Reproduction and integrity |
| `REPRODUCTION.md` | Fresh-environment reproduction record |
| `results/run_log.txt` | Raw console log of the fresh-environment `run_all.sh` run |

## Scope and limits (read before citing the numbers)

- **One probe run, one endpoint, one date.** All probe counts
  describe a single unauthenticated run on the fetch date above.
- **Guest perspective only.** ADMIN outcomes describe the guest view;
  per-deployment ADMIN configuration cannot be tested from here.
- **gRPC and WebSocket are code-derived only.** Their ports are not
  reachable from this machine; neither was probed live.
- **Origin TLS is not observable from this machine** (egress proxy
  re-signs the certificate).
- **No secret was ever sent.** Secret-accepting methods were probed
  with empty parameters; their signing behaviour is code-derived.
- **No build, no run.** A full build of the ledger is not feasible on
  the audit machine (no Conan, ~1 GB RAM available). Nothing in this
  pack claims the ledger was compiled or executed.
- **No live peer connections.** The harness uses only the public
  read-only JSON-RPC endpoint.
- See `assumptions.md` for the full list.
