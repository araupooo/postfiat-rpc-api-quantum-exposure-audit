# Primary sources

Every technical claim in this pack traces to one of these sources.
Line numbers refer to the pinned tree (postfiatd main commit
`0085a1ff885d6a446369cf73a4430f75af22be55`) unless stated otherwise.

## Pinned tree (postfiatd main, commit 0085a1ff)

- `src/xrpld/rpc/detail/Handler.cpp` — the JSON-RPC handler table:
  72 methods with role (`Role::USER` / `Role::ADMIN`) and condition
  (`NO_CONDITION` / `NEEDS_CURRENT_LEDGER` / `NEEDS_CLOSED_LEDGER` /
  `NEEDS_NETWORK_CONNECTION`); plus `addHandler<LedgerHandler>()` and
  `addHandler<VersionHandler>()` (lines 248–249).
- `src/xrpld/rpc/handlers/LedgerHandler.h:63,69` — `ledger` method,
  `Role::USER`.
- `src/xrpld/rpc/handlers/Version.h:49,55` — `version` method,
  `Role::USER`.
- `src/xrpld/rpc/detail/Handler.h:55-56` — default API version range
  1–3 (min `apiMinimumSupportedVersion`, max `apiMaximumValidVersion`).
- `include/xrpl/protocol/ApiVersion.h:56-62` — API versions: minimum
  supported 1, maximum supported 2, beta 3, maximum valid 3.
- `src/xrpld/rpc/detail/Role.cpp:89-118` — `requestRole`: ADMIN only
  when the caller IP is in the port's `admin` nets and the admin
  user/password (if configured) is correct; otherwise a request for an
  ADMIN method returns `Role::FORBID`. `isAdmin` (lines 84–92) and
  `passwordUnrequiredOrSentCorrect` (lines 26–44).
- `src/xrpld/rpc/detail/ServerHandler.cpp:752-757` — `Role::FORBID`
  over HTTP returns `HTTPReply(403, "Forbidden", ...)`.
- `src/xrpld/rpc/detail/RPCHandler.cpp:166-167` — the inner JSON-layer
  gate: an ADMIN handler with a non-ADMIN context returns
  `rpcNO_PERMISSION`.
- `src/libxrpl/server/Port.cpp:311-328` — per-port configuration:
  `admin` nets, `secure_gateway` nets, `admin_user`, `admin_password`,
  `ssl_key`, `ssl_cert`, `ssl_chain`, `ssl_ciphers`.
- `src/xrpld/rpc/detail/RPCHelpers.cpp:798-928` —
  `keypairForSignature`: `sign` / `sign_for` accept exactly one of
  `passphrase`, `secret`, `seed`, `seed_hex`; default key type is
  secp256k1 unless the seed encodes Ed25519.
- `src/xrpld/rpc/handlers/Submit.cpp:41-69` — `submit`: `tx_blob`
  path relays a pre-signed transaction; without `tx_blob` it falls
  back to server-side signing when `canSign()` is true, marked
  deprecated ("Signing support in the 'submit' command has been
  deprecated and will be removed in a future version").
- `src/xrpld/core/Config.h:365-368` — `canSign()` returns
  `signingEnabled_`.
- `src/xrpld/rpc/handlers/PayChanClaim.cpp:42-93,113-159` —
  `channel_authorize` (takes `secret`, returns a claim signature) and
  `channel_verify` (takes `public_key` + `signature`, verifies).
- `src/xrpld/rpc/handlers/WalletPropose.cpp:68-150` —
  `wallet_propose` (ADMIN): optional `passphrase` / `seed` / `seed_hex`
  input, otherwise a random seed; returns `master_seed`, `master_key`,
  account and public key.
- `src/xrpld/rpc/handlers/ValidationCreate.cpp:32-64` —
  `validation_create` (ADMIN): optional `secret` input; returns
  `validation_seed` and `validation_key` (secp256k1).
- `src/xrpld/rpc/handlers/Subscribe.cpp:116-167` — WebSocket
  subscription streams: `server`, `ledger`, `book_changes`,
  `manifests`, `transactions`, `transactions_proposed`,
  `rt_transactions` (deprecated), `validations`, `peer_status`,
  `consensus`.
- `src/xrpld/rpc/GRPCHandlers.h` — gRPC methods: `GetLedger`,
  `GetLedgerEntry`, `GetLedgerData`, `GetLedgerDiff`.
- `src/xrpld/app/main/GRPCServer.cpp:232-238,568-575` — gRPC role is
  `IDENTIFIED` or `USER` only (no ADMIN role); the server listens
  "without any authentication mechanism" (`InsecureServerCredentials`).
- `src/libxrpl/basics/make_SSLContext.cpp:90-104,347-375` — default
  TLS cipher list `TLSv1.2:!CBC:!DSS:!PSK:!eNULL:!aNULL`, overridable
  per port with `ssl_ciphers`.
- `src/xrpld/rpc/handlers/DoManifest.cpp:30-37` — `manifest` takes a
  `public_key` and returns that key's manifest.
- `src/xrpld/rpc/handlers/ServerInfo.cpp:299,322` —
  `server_definitions` and `server_info` (`pubkey_node`).
- `src/xrpld/rpc/handlers/Random.cpp:39-52` — `random` returns a
  256-bit CSPRNG value.
- `src/xrpld/app/misc/detail/ValidatorList.cpp:1643-1700` —
  `ValidatorList::getJson` returns `pubkey_publisher` for list
  publishers (returned by the ADMIN `validators` method).
- `src/xrpld/rpc/handlers/ValidatorInfo.cpp:34-50` —
  `validator_info` (ADMIN) returns this node's ephemeral validation
  public key.
- `src/xrpld/rpc/handlers/UnlList.cpp:34-38` — `unl_list` (ADMIN)
  returns `pubkey_validator` per listed validator.
- `src/libxrpl/protocol/PublicKey.cpp:224-236` — `publicKeyType`:
  33-byte key, `0xED` = Ed25519, `0x02`/`0x03` = secp256k1.
- `include/xrpl/protocol/HashPrefix.h:72` — `txSign` prefix used by
  `checkSingleSign` (`src/libxrpl/protocol/STTx.cpp:452`).

## Standards

- NIST FIPS 204 (Module-Lattice-Based Digital Signature Standard),
  Tables 1–2: ML-DSA-44 public key 1,312 B / signature 2,420 B;
  ML-DSA-65 1,952 B / 3,309 B; ML-DSA-87 2,592 B / 4,627 B.
- NIST FIPS 203 (ML-KEM), Table 2: ML-KEM-768 public key 1,184 B /
  ciphertext 1,088 B (cited in `migration_design.md` for the
  TLS 1.3 hybrid key-exchange sketch).

## Live measurements (this pack)

- Public read-only endpoint `https://rpc.testnet.postfiat.org/`,
  probed unauthenticated on the fetch date in
  `results/summary.json`. Raw responses (redacted, size-capped) in
  `results/probe_raw.json`; per-request outcomes in
  `results/fetch_log.json`.
- Transport observation recorded at authoring time with curl through
  the runtime egress proxy: TLS 1.3, `TLS_AES_256_GCM_SHA384`,
  X25519, ALPN http/1.1; certificate re-signed by the sandbox egress
  CA. The origin server's own TLS is not observable from this
  machine (see `assumptions.md`).

## Companion packs (same pinned tree)

- Historical ledger quantum-exposure audit (10 record classes; 142
  sampled transactions, all Ed25519 64-byte signatures; PQ
  checkpoints recommended): the sampled transaction hash used as a
  probe subject here comes from that pack's public sample.
- Consensus signature migration design (37 consensus-path call
  sites; ML-DSA-65 sizes; 5-phase migration; no rollback after
  activation). The migration phases in `migration_design.md` reuse
  its phase numbering and are cited, not re-derived.
