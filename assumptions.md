# Assumptions and limits — read before citing the numbers

- **A1 — One probe run, one endpoint, one date.** All probe counts
  describe a single unauthenticated probe run against
  `https://rpc.testnet.postfiat.org/` on the fetch date in
  `results/summary.json`. The endpoint's configuration, retained
  ledger range, and response behaviour can change; a later run may
  differ. The vendored `results/probe_raw.json` is the reproducible
  artifact, not a standing claim about the endpoint.
- **A2 — Unauthenticated guest perspective only.** Every probe was
  sent with no credentials, no admin user/password, and no client
  certificate. ADMIN-method outcomes describe the guest view only.
  Whether a particular deployment's ADMIN gate is correctly
  configured (admin nets, admin user/password) is a per-deployment
  fact this pack cannot test — it can only show that the public
  testnet endpoint refuses ADMIN methods with HTTP 403.
- **A3 — HTTP 403 is the observed ADMIN refusal.** All 23 ADMIN
  methods were refused with HTTP 403 and body `Forbidden` (plain
  text, 11 bytes). That matches the code path
  `requestRole` → `Role::FORBID` (`Role.cpp:105-106`) → HTTP 403
  (`ServerHandler.cpp:752-757`). The inner JSON-layer gate
  (`rpcNO_PERMISSION`, `RPCHandler.cpp:166`) was not observed live
  because the HTTP layer refuses first; its existence is a
  code-derived claim.
- **A4 — Transient transport failures are recorded, not hidden.**
  Four probes failed at transport on the first run
  (`RemoteDisconnected` after 3 tries each) and succeeded or were
  re-classified on the re-run. Any `transport_error` remaining in
  the final results is a network failure, not a refusal — it means
  "no answer", not "forbidden".
- **A5 — No secret was ever sent.** Probes of secret-accepting
  methods (`sign`, `sign_for`, `channel_authorize`, `submit`,
  `submit_multisigned`, `validation_create`, `wallet_propose`) used
  empty parameters. Their outcomes therefore show the missing-field
  or gate behaviour, not the signing behaviour. Claims about what
  these methods do with a secret come from reading the handler code,
  not from a live signing test. No signature was produced by this
  pack, and no transaction was submitted.
- **A6 — Responses are redacted and size-capped.** Any value under a
  sensitive key (`secret`, `seed`, `seed_hex`, `master_seed`,
  `validation_seed`, `passphrase`, `private_key`, `admin_password`,
  `admin_user`, `password`) is replaced with `<redacted>` before
  storage, and responses over 32 KiB are stored truncated (head +
  SHA-256 + top-level keys). No secret material is present in the
  pack. The redaction count per response is recorded in
  `results/probe_raw.json`.
- **A7 — gRPC and WebSocket are code-derived only.** The public
  endpoint's gRPC port (50051) and WebSocket port (6005) are listed
  in `server_info` but are not reachable from this machine (only
  port 443 via the runtime egress proxy). The 4 gRPC methods and 10
  WebSocket streams were inventoried from code, not probed live.
  Nothing is claimed about their live behaviour.
- **A8 — Origin TLS is not observable from this machine.** The TLS
  session observed (TLS 1.3, `TLS_AES_256_GCM_SHA384`, X25519)
  terminates at the runtime egress proxy, which re-signs the
  certificate (sandbox egress CA). No claim is made about the
  origin server's TLS version, cipher list, or certificate. The
  code's default cipher list (`TLSv1.2:!CBC:!DSS:!PSK:!eNULL:!aNULL`,
  `make_SSLContext.cpp:104`) is a code-derived claim about the
  default, not a measurement of the public endpoint.
- **A9 — The node public key is public by design.** `server_info`
  returns `pubkey_node` and `manifest` returns manifests for any
  public key. Recording these values is recording public ledger
  data; no private material is involved.
- **A10 — Ledger not compiled or executed.** The inventory is static
  analysis of the pinned tree plus read-only RPC probing. No claim
  is made that the ledger was built or run. Handler line numbers
  refer to the pinned tree as checked out at authoring time.
- **A11 — Cost figures are estimates.** ML-DSA signature sizes are
  from FIPS 204 (exact standard values). Migration cost figures in
  `migration_design.md` (bytes per call, storage, verification time)
  are arithmetic from those sizes and from measured per-call sizes;
  they are labelled estimates where they depend on unmeasured
  quantities (e.g. verification throughput on node hardware).
- **A12 — No claim about when a cryptographically relevant quantum
  computer will exist.** The pack assesses what the API surface
  exposes to a future adversary; it makes no timeline claim.
- **A13 — `submit` signing path is deprecated but present.**
  `Submit.cpp:56-69` marks server-side signing in `submit` as
  deprecated. The pack reports the code as it stands at the pinned
  commit; a future release may remove the path.
- **A14 — Probe account and transaction are public data.** The
  probe account and transaction hash are public ledger records
  (the account transacted in the companion pack's public sample).
  Using them as read-only probe subjects discloses nothing private.
