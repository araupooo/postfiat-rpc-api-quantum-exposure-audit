# Per-method quantum-exposure analysis

What a future quantum adversary can harvest, forge, or inject through
each part of the PFTL API surface — measured live where possible,
derived from code where the live probe cannot reach.

Probe: unauthenticated, 2026-11-13T20:57:45Z, endpoint
`https://rpc.testnet.postfiat.org/`. 74 methods probed: **32 success,
19 RPC error, 23 HTTP 403 Forbidden, 0 transport errors.**
Raw responses: `results/probe_raw.json`. Per-method rows:
`results/probe_results.csv`.

## 1. The harvest surface (what the API hands out for free)

Six methods returned a public key or signature field in their live
response:

| Method | What came back |
|---|---|
| `account_tx` | 5 transactions, each with `SigningPubKey` `ED4B56…` (Ed25519, `0xED` prefix) and a `TxnSignature` |
| `tx` | `SigningPubKey` `EDDD99…` (Ed25519) and `TxnSignature` `28456086…` for the probe transaction |
| `transaction_entry` | Same `SigningPubKey` / `TxnSignature` as `tx`, with full metadata |
| `manifest` | `details.ephemeral_key` and `details.master_key`, both `n9K4Aom…` — the node's validator key, twice: this node validates with its master key directly, with no separate ephemeral key |
| `server_info` | `pubkey_node` `n9K4AomBUHA8XGwXtZs6qfCjXm5aXre9UchiD6oGuZx1UeRLUweE` (secp256k1 node key) plus listening ports (2559 peer, 6005 ws, 50051 grpc) |
| `server_state` | `state.pubkey_node`, same key |

Three more methods are in the PUBKEY_OUT class by code but returned
no key-carrying record in the probed responses: `ledger` (probed with
`transactions:false`, so no transaction JSON was returned),
`ledger_data` (page of 5 `AccountRoot` entries, no payment channel),
`ledger_entry` (an `AccountRoot` record, which carries no key). They
return keys when the requested data includes them — `ledger` with
`transactions:true`, `ledger_data` / `ledger_entry` for an
`ltPAYCHAN` entry, whose `sfPublicKey` is the only public-key field
in any ledger entry type (companion historical-ledger pack, S-06).

The read surface needs **no migration**: it only relays what the
ledger already records publicly. Its consumers must be ready to
*verify* ML-DSA signatures once hybrid transactions exist, but the
methods themselves neither sign nor store secrets.

## 2. The signing surface (where new signatures are made)

Four methods can produce a signature, and all four are reachable
without authentication (USER role). On the probed node all four are
closed by configuration, not by code:

| Method | Code | Live outcome on the probed node |
|---|---|---|
| `sign` | Takes exactly one of `passphrase` / `secret` / `seed` / `seed_hex` (`RPCHelpers.cpp:798-928`), returns a signed `tx_blob` / `tx_json` | `notSupported` (75): "Signing is not supported by this server." |
| `sign_for` | Same, for multi-signed transactions (`SignFor.cpp:37-40`) | `notSupported` (75) |
| `channel_authorize` | Takes a secret, returns a payment-channel claim signature (`PayChanClaim.cpp:44-47`) | `notSupported` (75) |
| `submit` | `tx_blob` path relays a pre-signed transaction; `tx_json` + `secret` path signs server-side when signing is enabled, marked deprecated (`Submit.cpp:41-69`) | `notSupported` (75) for the signing path |

The gate is `context.role != Role::ADMIN && !context.app.config().canSign()`
(`SignHandler.cpp:36-39`, `SignFor.cpp:37-40`,
`PayChanClaim.cpp:44-47`, `Submit.cpp:53-57`). `canSign()` returns
`signingEnabled_` (`Config.h:365-368`). **On this deployment signing
is disabled, so a guest cannot get the node to sign anything — but
that is a configuration choice.** Any deployment with signing enabled
exposes all four to anyone who can reach the RPC port, and every
secret sent to them travels in the request body, visible to the
endpoint operator and to any TLS-terminating proxy in front of it.
The signing entry points are the first thing that must gain hybrid
classical + ML-DSA signing (see `migration_design.md`).

`submit_multisigned` (`SIG_RELAY`) relays a fully multi-signed
transaction; it signs nothing. It returned `invalidParams`
("Missing field 'tx_json'") when probed with empty parameters, as
expected. `channel_verify` (`SIG_VERIFY`) verifies a supplied
signature against a supplied public key and signs nothing; it
returned `invalidParams` ("Missing field 'public_key'") with empty
parameters. Neither is a forgery oracle: `channel_verify` only
answers whether a given signature is valid.

## 3. The ADMIN gate (the only thing between a guest and secret generation)

All 23 ADMIN methods were refused with **HTTP 403 `Forbidden`**
(plain-text body, 11 bytes) — not with the JSON `noPermission`
error. The mechanism is two-layer:

1. **HTTP layer** (`Role.cpp:96-118` → `ServerHandler.cpp:752-757`):
   `requestRole` returns `Role::FORBID` for a non-admin caller asking
   for an ADMIN method, and the server answers HTTP 403. This is what
   was observed live for all 23 methods.
2. **JSON layer** (`RPCHandler.cpp:166-167`): an ADMIN handler with a
   non-ADMIN context returns `rpcNO_PERMISSION`. This was not
   observed live because the HTTP layer refuses first; it is a
   code-derived claim.

ADMIN is granted when the caller IP is in the port's `admin` nets
and, if configured, the correct `admin_user` / `admin_password` is
presented (`Role.cpp:84-92`, `Port.cpp:311-328`). **The gate is only
as strong as the per-port configuration.** The two most sensitive
ADMIN methods are the secret generators:

| Method | What it returns if the gate fails open |
|---|---|
| `wallet_propose` | `master_seed`, `master_key`, account, public key for a fresh or supplied seed (`WalletPropose.cpp:68-150`) |
| `validation_create` | `validation_seed` and `validation_key` for a validator identity (`ValidationCreate.cpp:32-64`) |

Both were probed with empty parameters and refused with HTTP 403, so
no secret material was returned (redaction count in the probe: 0).
The remaining 21 ADMIN methods are control operations (`stop`,
`ledger_accept`, `peers`, `log_level`, `validators`, `unl_list`,
`validator_info`, …) — privileged, but they return no secrets. Note
`validator_info` and `validators` return validator public keys, and
`unl_list` returns `pubkey_validator` per listed validator; those
keys are public by design, but the methods are still ADMIN-gated.

## 4. The transport layer

- The code's default TLS cipher list is
  `TLSv1.2:!CBC:!DSS:!PSK:!eNULL:!aNULL`
  (`src/libxrpl/basics/make_SSLContext.cpp:104`), overridable per port
  with `ssl_ciphers`. TLS 1.3 negotiation depends on the OpenSSL
  build; the pinned tree vendors OpenSSL 1.1.1w, which supports
  TLS 1.3 but has no ML-KEM.
- The public endpoint was observed (curl, through the runtime egress
  proxy) negotiating **TLS 1.3, `TLS_AES_256_GCM_SHA384`, X25519, ALPN
  http/1.1**. The certificate presented was re-signed by the sandbox
  egress CA — the TLS session terminates at the proxy, so the origin
  server's own TLS version, cipher and certificate are **not
  observable from this machine** and no claim is made about them
  (`assumptions.md` A8).
- gRPC (`GetLedger`, `GetLedgerEntry`, `GetLedgerData`,
  `GetLedgerDiff`) listens with `InsecureServerCredentials()` — **no
  authentication at all** (`GRPCServer.cpp:568-575`) — and assigns
  only `USER`/`IDENTIFIED` roles (`GRPCServer.cpp:232-238`). Anyone
  who can reach the gRPC port (50051) can read ledger data. The
  methods are read-only, so the exposure is bounded to reads, but
  there is no gate at all to audit.
- `server_info` advertises the node's listening ports (2559 peer,
  6005 ws, 50051 grpc) to any unauthenticated caller. Port
  advertisement is standard XRPL behaviour, not a vulnerability,
  but it tells an attacker exactly where the unauthenticated gRPC
  and WebSocket services live.

## 5. WebSocket-only surface (code-derived)

`subscribe` over plain HTTP POST returns `invalidParams`; `path_find`
(subcommand `create`) over HTTP returns `noEvents` ("Current
transport does not support events"). Both need a WebSocket
connection, which this harness cannot open. The streams that matter
for quantum exposure are `validations` (live validator public keys
and signatures as they arrive), `transactions` /
`transactions_proposed` (live `SigningPubKey` / `TxnSignature`), and
`manifests` (validator manifests as they arrive). A WebSocket
subscriber is a **live harvest** tap: it receives signatures the
moment they are gossiped, years before they are needed. That surface
was inventoried from code (`Subscribe.cpp:116-167`), not probed live.

## 6. Feature flags and dead ends (measured)

- `exclusion_info` returns `notEnabled` (12): the
  `PF_AccountExclusion` feature is not enabled on this network.
- `book_offers` for XRP/XRP returns `badMarket` (42): no such market
  — the method works, the book does not exist.
- `ripple_path_find` rejects XRP destination amounts
  (`dstAmtMalformed`, 51); an IOU destination amount succeeds
  (alternatives: `[]`).
- `nft_buy_offers` / `nft_sell_offers` for a real token id return
  `objectNotFound` (92): the token exists, it has no offers.
- `validator_votes` with the node public key returns
  `invalidValidatorPublicKey`: the node key is not a validator key
  in the format the method expects.
- `tx_history` (API v1) with empty parameters returns
  `invalidParams`; it needs a `start` index.
- `account_info` for the probe account returns `account_data` with
  no key field — confirming the SAFE classification. Its
  `PreviousTxnID` (`2FA84094723736800A5E3109A17FE7579A3EF87E4F390F0DD279591AE2768633`)
  is the hash of the most recent transaction for this account, a
  Payment at ledger 8022102 (`PreviousTxnLgrSeq`), which also appears
  in the `account_tx` probe response.

## 7. What would break, in order

1. **A broken account key** lets an adversary submit new
   transactions as the account through `submit` / `submit_multisigned`
   — the same conclusion as the historical-ledger pack. The API adds
   nothing new here except the injection point.
2. **A broken validator key** lets an adversary sign validations —
   but validations are only visible live (`validations` stream,
   `manifest`), never through the JSON-RPC read methods except
   `manifest` and `validator_votes` (key lookup).
3. **A misconfigured ADMIN gate** is the highest-severity API-specific
   risk: `wallet_propose` / `validation_create` would generate and
   return secrets to any caller, and `stop` / `ledger_accept` /
   `connect` would hand control of the node to a guest. The gate held
   on the probed endpoint (23/23 HTTP 403), but it is configuration,
   not cryptography.
4. **Signing enabled on a public node** (`canSign() == true`) would
   turn `sign`, `sign_for`, `channel_authorize` and the deprecated
   `submit` signing path into a public signing oracle for anyone who
   supplies a secret — and the secrets themselves would be exposed to
   the operator and any proxy. On the probed node signing is disabled.
