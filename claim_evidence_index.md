# Claim-to-evidence index

Every headline claim in this pack, mapped to the repo file, field, and
line that holds it. Line numbers refer to the files as published in
this repository. Pinned tree: postfiatd main commit
`0085a1ff885d6a446369cf73a4430f75af22be55`. Harness:
`harness.py` 1.0.0. Probe: unauthenticated, 2026-11-13T20:57:45Z,
public read-only endpoint `https://rpc.testnet.postfiat.org/`.

## Measured claims (from running the harness)

| # | Claim | Evidence |
|---|-------|----------|
| M-01 | 74 JSON-RPC methods probed live, unauthenticated: 32 success, 19 RPC error, 23 HTTP 403 Forbidden, 0 transport errors | `results/summary.json`, `outcomes` lines 65–70, `probed_total` line 71; `results/summary.txt`, lines 9–10; `results/fetch_log.json`, 74 entries |
| M-02 | All 23 ADMIN methods refused with HTTP 403 Forbidden (plain-text body `Forbidden`) | `results/summary.json`, `admin_gate` lines 2–32 (`refused_no_permission` line 30, `admin_total` line 3); `results/probe_results.csv`, rows for the 23 ADMIN methods (e.g. `blacklist` line 11, `wallet_propose` line 94); `results/fetch_log.json`, line 118 (`blacklist`) and line 778 (`wallet_propose`) |
| M-03 | Signing is disabled on the probed node: `sign`, `sign_for`, `channel_authorize` and `submit` all return `notSupported` (75), "Signing is not supported by this server." | `results/summary.json`, `error_codes` lines 33–42 (`notSupported` 4); `results/probe_raw.json`, `probes.sign` line 3114, `probes.sign_for` line 3150, `probes.channel_authorize` line 1025, `probes.submit` line 3247 (each `response.result.error: notSupported`); `results/probe_results.csv`, `sign` line 71, `sign_for` line 72, `submit` line 76 |
| M-04 | 6 methods returned a public-key or signature field in their live response: `account_tx`, `manifest`, `server_info`, `server_state`, `transaction_entry`, `tx` | `results/summary.json`, `pubkey_fields_observed_live` lines 83–91; `results/summary.txt`, line 18 |
| M-05 | `account_tx` returned 5 transactions, all with Ed25519 `SigningPubKey` (`0xED` prefix) and a `TxnSignature` | `results/probe_raw.json`, `probes.account_tx` line 389 (5 transactions; first key `ED4B56…`); `results/summary.txt`, line 18 |
| M-06 | Server snapshot: build 1.0.9, network_id 2025, validated ledger 8023087, complete_ledgers 7950054–8023087, 21 peers, validation quorum 17, node public key `n9K4Aom…` | `results/summary.json`, `server_snapshot` lines 104–133 (`build_version` line 105, `network_id` line 107, `validated_ledger_seq` line 131, `pubkey_node` line 129); `results/summary.txt`, lines 20–21 |
| M-07 | Error-code breakdown: `invalidParams` 8, `notSupported` 4, `objectNotFound` 2, `badMarket` 1, `invalidValidatorPublicKey` 1, `malformedRequest` 1, `noEvents` 1, `notEnabled` 1 | `results/summary.json`, `error_codes` lines 33–42; `results/summary.txt`, line 11; `results/method_counts.csv`, `error_code` rows |
| M-08 | Exposure counts: SAFE 33, PUBKEY_OUT 14, STATE 18, SECRET_IN 6, SECRET_OUT 2, SIG_OUT 3, SIG_RELAY 2, PUBKEY_IN 1, SIG_VERIFY 1 | `results/summary.json`, `exposure_counts` lines 43–53; `results/method_counts.csv`, `exposure_class` rows; `api_inventory.csv`, 75 lines (header + 74 methods) |
| M-09 | Transport observed via the egress proxy: TLS 1.3, cipher `TLS_AES_256_GCM_SHA384`, X25519, ALPN http/1.1; origin TLS not observable (certificate re-signed by the sandbox egress CA) | `results/summary.json`, `transport_observation` lines 139–148 (`tls_version` line 146, `cipher` line 142) |
| M-10 | The embedded method inventory matches a fresh parse of the handler table, and the tree HEAD matches the pinned commit | `results/summary.json`, `handler_table_check` lines 56–61 (`matches: true`), `tree_check` lines 149–152 (`tree_head_matches_pinned` line 151); `results/summary.txt`, lines 5–6 |
| M-11 | No secret material was returned by any probe (redaction count 0) and no secret, seed or passphrase was ever sent | `results/probe_raw.json` (0 redactions across all 74 `response_meta` entries); `harness.py`, `probe_params` (no secret-bearing params) and `SENSITIVE_KEYS` redaction |
| M-12 | `path_find` (subcommand `create`) over HTTP returns `noEvents` ("Current transport does not support events"); `subscribe` over HTTP returns `invalidParams` — both need a WebSocket | `results/summary.json`, `error_codes` lines 33–42 (`noEvents` 1, `invalidParams` 8); `results/probe_raw.json`, `probes.path_find` and `probes.subscribe` entries |
| M-13 | The probed node validates with its master key directly: `manifest` returns `ephemeral_key` == `master_key` == `n9K4Aom…` | `results/probe_raw.json`, `probes.manifest` line 2395 (`details.ephemeral_key` and `details.master_key`, identical) |
| M-14 | The probed `ledger_data` page (5 entries, all `AccountRoot`) and the probed `ledger_entry` (`AccountRoot`) and `account_info` (`account_data`) returned no key field | `results/probe_raw.json`, `probes.ledger_data`, `probes.ledger_entry`, `probes.account_info` entries (no `SigningPubKey` / `sfPublicKey` in any stored response) |

## Source-derived claims (from the pinned tree and primary sources)

| # | Claim | Evidence |
|---|-------|----------|
| S-01 | The JSON-RPC surface is 74 methods: 72 in the handler table plus `ledger` and `version` new-style handlers; 51 USER, 23 ADMIN | Pinned tree: `src/xrpld/rpc/detail/Handler.cpp`, lines 83–200 (table), 248–249 (`addHandler`); `src/xrpld/rpc/handlers/LedgerHandler.h`, lines 63 and 69; `src/xrpld/rpc/handlers/Version.h`, lines 49 and 55. Cited in `api_inventory.md`, lines 1–15 and 50–128; `api_inventory.csv`, 75 lines |
| S-02 | ADMIN is granted only to IPs in the port's `admin` nets with the correct admin user/password if configured; a non-admin caller asking for an ADMIN method gets `Role::FORBID`, answered over HTTP with 403 `Forbidden`; the JSON layer has a second gate, `rpcNO_PERMISSION` | Pinned tree: `src/xrpld/rpc/detail/Role.cpp`, lines 84–118; `src/libxrpl/server/Port.cpp`, lines 311–328; `src/xrpld/rpc/detail/ServerHandler.cpp`, lines 752–757; `src/xrpld/rpc/detail/RPCHandler.cpp`, lines 166–167. Cited in `api_inventory.md`, lines 17–29; `exposure_analysis.md`, lines 76–110 |
| S-03 | `sign` / `sign_for` accept exactly one of `passphrase`, `secret`, `seed`, `seed_hex`; default key type is secp256k1 unless the seed encodes Ed25519 | Pinned tree: `src/xrpld/rpc/detail/RPCHelpers.cpp`, lines 798–928 (`keypairForSignature`); `src/xrpld/rpc/handlers/SignHandler.cpp`, lines 36–39; `src/xrpld/rpc/handlers/SignFor.cpp`, lines 37–40. Cited in `api_inventory.md`, lines 129–205; `exposure_analysis.md`, lines 42–75 |
| S-04 | `submit` with `tx_blob` relays a pre-signed transaction; without it, it signs server-side when signing is enabled — deprecated and to be removed | Pinned tree: `src/xrpld/rpc/handlers/Submit.cpp`, lines 41–69; `src/xrpld/core/Config.h`, lines 365–368 (`canSign`). Cited in `exposure_analysis.md`, lines 42–75; `migration_design.md`, lines 8–44 |
| S-05 | `channel_authorize` takes a secret and returns a claim signature; `channel_verify` takes a public key and signature and verifies only | Pinned tree: `src/xrpld/rpc/handlers/PayChanClaim.cpp`, lines 42–93 and 113–159. Cited in `api_inventory.md`, lines 129–205; `exposure_analysis.md`, lines 42–75 |
| S-06 | `wallet_propose` (ADMIN) returns `master_seed`, `master_key` and account for a supplied or random seed; `validation_create` (ADMIN) returns `validation_seed` and `validation_key` | Pinned tree: `src/xrpld/rpc/handlers/WalletPropose.cpp`, lines 68–150; `src/xrpld/rpc/handlers/ValidationCreate.cpp`, lines 32–64. Cited in `api_inventory.md`, lines 129–205; `exposure_analysis.md`, lines 76–110 |
| S-07 | gRPC listens with no authentication (`InsecureServerCredentials`) and assigns only USER/IDENTIFIED roles; its 4 methods are read-only ledger reads | Pinned tree: `src/xrpld/app/main/GRPCServer.cpp`, lines 232–238 and 568–575; `src/xrpld/rpc/GRPCHandlers.h`. Cited in `api_inventory.md`, lines 206–224; `exposure_analysis.md`, lines 111–138 |
| S-08 | WebSocket streams are `server`, `ledger`, `book_changes`, `manifests`, `transactions`, `transactions_proposed`, `rt_transactions` (deprecated), `validations`, `peer_status`, `consensus`; `validations`, `transactions` and `manifests` carry keys and signatures live | Pinned tree: `src/xrpld/rpc/handlers/Subscribe.cpp`, lines 116–167. Cited in `api_inventory.md`, lines 225–248; `exposure_analysis.md`, lines 139–152 |
| S-09 | The code's default TLS cipher list is `TLSv1.2:!CBC:!DSS:!PSK:!eNULL:!aNULL`, overridable per port with `ssl_ciphers` | Pinned tree: `src/libxrpl/basics/make_SSLContext.cpp`, lines 90–104 and 347–375; `src/libxrpl/server/Port.cpp`, line 327. Cited in `api_inventory.md`, lines 249–257; `exposure_analysis.md`, lines 111–138 |
| S-10 | ML-DSA sizes are FIPS 204 Table 2: ML-DSA-44 1,312 B pk / 2,420 B sig; ML-DSA-65 1,952 B / 3,309 B, secret key 4,032 B; ML-DSA-87 2,592 B / 4,627 B. ML-KEM-768 is 1,184 B pk / 1,088 B ct (FIPS 203 Table 2) | NIST FIPS 204, Tables 1–2; NIST FIPS 203, Table 2; documented in `sources.md`, "Standards"; used in `migration_design.md`, lines 45–80 |
| S-11 | ADMIN methods return validator public keys: `unl_list` returns `pubkey_validator`, `validators` returns `pubkey_publisher`, `validator_info` returns the node's ephemeral validation public key | Pinned tree: `src/xrpld/rpc/handlers/UnlList.cpp`, lines 34–38; `src/xrpld/app/misc/detail/ValidatorList.cpp`, lines 1643–1700 (`pubkey_publisher`); `src/xrpld/rpc/handlers/ValidatorInfo.cpp`, lines 34–50. Cited in `exposure_analysis.md`, lines 76–110 |
| S-12 | API versions are 1 (minimum supported) to 3 (maximum valid); default handler range is 1–3, and `ledger_header` and `tx_history` are API v1 only | Pinned tree: `include/xrpl/protocol/ApiVersion.h`, lines 56–62; `src/xrpld/rpc/detail/Handler.h`, lines 55–56; `src/xrpld/rpc/detail/Handler.cpp` (`ledger_header` and `tx_history` entries with range 1, 1). Cited in `api_inventory.md`, lines 50–128 |

## Design judgements (not measurements)

| # | Claim | Evidence |
|---|-------|----------|
| D-01 | Migrate the four signing entry points to hybrid classical + ML-DSA-65; leave the read surface unchanged; harden the ADMIN gate per deployment now; add TLS + authentication to gRPC | `migration_design.md`, sections 1–3, lines 8–123. This is a judgement from the measured probe (M-02, M-03, M-04) and the code-derived surface (S-02, S-07). |
| D-02 | After the activation amendment there is no protocol rollback; recovery is forward-only | `migration_design.md`, section 3, Phase 4, lines 81–123; the amendment mechanism has no disable path for enabled amendments (companion consensus migration pack). |
| D-03 | ML-DSA-65 is the recommended parameter set (category 3); ML-DSA-44 is smaller but category 1, ML-DSA-87 is category 5 and 40% larger per signature | `migration_design.md`, section 2, lines 45–80; sizes from FIPS 204 Table 2 (S-10). |

## What is NOT claimed (limits)

- No claim that the ADMIN gate is correctly configured on any
  deployment other than the probed endpoint — only that the probed
  endpoint refuses all 23 ADMIN methods with HTTP 403 (M-02; A2).
- No claim about the origin server's TLS version, cipher, or
  certificate — only what was observed through the egress proxy
  (M-09; A8).
- No claim that gRPC or WebSocket behaviour was measured live —
  both surfaces are code-derived only (A7).
- No claim that any secret was handled, signed, or submitted — no
  secret was ever sent, and the signing methods were probed with
  empty parameters only (M-11; A5).
- No claim that the ledger was compiled or executed — it was not
  (A10).
- No claim about when a cryptographically relevant quantum computer
  will exist (A12).
- No claim that the `ledger`, `ledger_data` or `ledger_entry`
  responses in this probe contained a key — they did not (M-14);
  their PUBKEY_OUT classification is code-derived (conditional on
  the requested data).
- No claim about verification throughput on node hardware — it is
  unmeasured (migration Q3).

## Reproduction

Run `bash run_all.sh` from a fresh copy of this repository: it re-runs
the harness in offline mode from the vendored sample, rebuilds
`docs/index.html`, regenerates `SHA256SUMS`, and verifies digests.
Expected: exit 0, all derived outputs byte-identical to the shipped
files. See `REPRODUCTION.md` for the exact command and recorded
result, and `results/run_log.txt` for the raw console log of the
fresh-environment run. Verify digests at any time with
`bash verify_digests.sh --check`.
