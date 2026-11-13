# API inventory

The complete API surface of the pinned postfiatd tree (main commit
`0085a1ff885d6a446369cf73a4430f75af22be55`), inventoried from the
handler table in `src/xrpld/rpc/detail/Handler.cpp` (72 methods) plus
the two new-style handlers `LedgerHandler` (`ledger`) and
`VersionHandler` (`version`), and probed live from an unauthenticated
client on 2026-11-13T20:57:45Z.

**74 JSON-RPC methods: 51 USER, 23 ADMIN.** Plus 4 gRPC methods and
10 WebSocket subscription streams (code-derived only — see below).

The embedded inventory was cross-checked against a fresh parse of
`Handler.cpp` by the harness (`tree_table_check.matches: true` in
`results/summary.json`).

## Roles

- **USER** — any caller may invoke the method (subject to resource
  limits). 51 methods.
- **ADMIN** — the caller must be an administrator: its IP must be in
  the port's `admin` nets and, if configured, it must present the
  correct `admin_user` / `admin_password` (`Role.cpp:84-118`,
  `Port.cpp:311-328`). A non-admin caller is refused at the HTTP
  layer with HTTP 403 `Forbidden` (`ServerHandler.cpp:752-757`); the
  JSON layer has a second gate, `rpcNO_PERMISSION`
  (`RPCHandler.cpp:166-167`). 23 methods. All 23 were refused with
  HTTP 403 when probed unauthenticated.

## Exposure classes

- **SAFE** — no key material in request or response.
- **PUBKEY_OUT** — returns public keys and/or signed data (the
  harvest surface). 14 methods.
- **PUBKEY_IN** — takes a public key as input (lookup by key).
  1 method.
- **SECRET_IN** — accepts a secret, seed, passphrase or seed_hex in
  the request body. 6 methods.
- **SECRET_OUT** — generates or returns secret material. 2 methods
  (both ADMIN).
- **SIG_OUT** — produces a signature (signing entry point).
  3 methods.
- **SIG_VERIFY** — verifies a supplied signature against a supplied
  public key; signs nothing. 1 method.
- **SIG_RELAY** — relays a pre-signed transaction; signs nothing.
  2 methods.
- **STATE** — privileged control operation, no key material.
  18 methods (all ADMIN).

## JSON-RPC methods

| Method | Role | Condition | Handler (file:line) | API | Exposure | Probe outcome |
|---|---|---|---|---|---|---|
| `account_info` | USER | NO_CONDITION | `src/xrpld/rpc/handlers/AccountInfo.cpp:50` | 1-3 | SAFE | success () |
| `account_currencies` | USER | NO_CONDITION | `src/xrpld/rpc/handlers/AccountCurrenciesHandler.cpp:32` | 1-3 | SAFE | success () |
| `account_lines` | USER | NO_CONDITION | `src/xrpld/rpc/handlers/AccountLines.cpp:81` | 1-3 | SAFE | success () |
| `account_channels` | USER | NO_CONDITION | `src/xrpld/rpc/handlers/AccountChannels.cpp:68` | 1-3 | SAFE | success () |
| `account_nfts` | USER | NO_CONDITION | `src/xrpld/rpc/handlers/AccountObjects.cpp:50` | 1-3 | SAFE | success () |
| `account_objects` | USER | NO_CONDITION | `src/xrpld/rpc/handlers/AccountObjects.cpp:181` | 1-3 | SAFE | success () |
| `account_offers` | USER | NO_CONDITION | `src/xrpld/rpc/handlers/AccountOffers.cpp:57` | 1-3 | SAFE | success () |
| `account_tx` | USER | NO_CONDITION | `src/xrpld/rpc/handlers/AccountTx.cpp:408` | 1-3 | PUBKEY_OUT | success () |
| `amm_info` | USER | NO_CONDITION | `src/xrpld/rpc/handlers/AMMInfo.cpp:76` | 1-3 | SAFE | rpc_error (invalidParams) |
| `blacklist` | ADMIN | NO_CONDITION | `src/xrpld/rpc/handlers/BlackList.cpp:29` | 1-3 | STATE | http_forbidden (http_403_forbidden) |
| `book_changes` | USER | NO_CONDITION | `src/xrpld/rpc/handlers/BookOffers.cpp:222` | 1-3 | SAFE | success () |
| `book_offers` | USER | NO_CONDITION | `src/xrpld/rpc/handlers/BookOffers.cpp:37` | 1-3 | SAFE | rpc_error (badMarket) |
| `can_delete` | ADMIN | NO_CONDITION | `src/xrpld/rpc/handlers/CanDelete.cpp:35` | 1-3 | STATE | http_forbidden (http_403_forbidden) |
| `channel_authorize` | USER | NO_CONDITION | `src/xrpld/rpc/handlers/PayChanClaim.cpp:42` | 1-3 | SECRET_IN|SIG_OUT | rpc_error (notSupported) |
| `channel_verify` | USER | NO_CONDITION | `src/xrpld/rpc/handlers/PayChanClaim.cpp:113` | 1-3 | SIG_VERIFY | rpc_error (invalidParams) |
| `connect` | ADMIN | NO_CONDITION | `src/xrpld/rpc/handlers/Connect.cpp:39` | 1-3 | STATE | http_forbidden (http_403_forbidden) |
| `consensus_info` | ADMIN | NO_CONDITION | `src/xrpld/rpc/handlers/ConsensusInfo.cpp:30` | 1-3 | STATE | http_forbidden (http_403_forbidden) |
| `deposit_authorized` | USER | NO_CONDITION | `src/xrpld/rpc/handlers/DepositAuthorized.cpp:41` | 1-3 | SAFE | success () |
| `exclusion_info` | USER | NO_CONDITION | `src/xrpld/rpc/handlers/ExclusionInfo.cpp:35` | 1-3 | SAFE | rpc_error (notEnabled) |
| `feature` | USER | NO_CONDITION | `src/xrpld/rpc/handlers/Feature1.cpp:36` | 1-3 | SAFE | success () |
| `fee` | USER | NEEDS_CURRENT_LEDGER | `src/xrpld/rpc/handlers/Fee1.cpp:30` | 1-3 | SAFE | success () |
| `fetch_info` | ADMIN | NO_CONDITION | `src/xrpld/rpc/handlers/FetchInfo.cpp:30` | 1-3 | STATE | http_forbidden (http_403_forbidden) |
| `gateway_balances` | USER | NO_CONDITION | `src/xrpld/rpc/handlers/GatewayBalances.cpp:54` | 1-3 | SAFE | success () |
| `get_counts` | ADMIN | NO_CONDITION | `src/xrpld/rpc/handlers/GetCounts.cpp:138` | 1-3 | STATE | http_forbidden (http_403_forbidden) |
| `get_aggregate_price` | USER | NO_CONDITION | `src/xrpld/rpc/handlers/GetAggregatePrice.cpp:153` | 1-3 | SAFE | rpc_error (invalidParams) |
| `ledger` | USER | NO_CONDITION | `src/xrpld/rpc/handlers/LedgerHandler.h:63` | 1-3 | PUBKEY_OUT | success () |
| `ledger_accept` | ADMIN | NEEDS_CURRENT_LEDGER | `src/xrpld/rpc/handlers/LedgerAccept.cpp:34` | 1-3 | STATE | http_forbidden (http_403_forbidden) |
| `ledger_cleaner` | ADMIN | NEEDS_NETWORK_CONNECTION | `src/xrpld/rpc/handlers/LedgerCleanerHandler.cpp:30` | 1-3 | STATE | http_forbidden (http_403_forbidden) |
| `ledger_closed` | USER | NEEDS_CLOSED_LEDGER | `src/xrpld/rpc/handlers/LedgerClosed.cpp:30` | 1-3 | SAFE | success () |
| `ledger_current` | USER | NEEDS_CURRENT_LEDGER | `src/xrpld/rpc/handlers/LedgerCurrent.cpp:30` | 1-3 | SAFE | success () |
| `ledger_data` | USER | NO_CONDITION | `src/xrpld/rpc/handlers/LedgerData.cpp:46` | 1-3 | PUBKEY_OUT | success () |
| `ledger_entry` | USER | NO_CONDITION | `src/xrpld/rpc/handlers/LedgerEntry.cpp:755` | 1-3 | PUBKEY_OUT | success () |
| `ledger_header` | USER | NO_CONDITION | `src/xrpld/rpc/handlers/LedgerHeader.cpp:34` | 1 | SAFE | success () |
| `ledger_request` | ADMIN | NO_CONDITION | `src/xrpld/rpc/handlers/LedgerRequest.cpp:36` | 1-3 | STATE | http_forbidden (http_403_forbidden) |
| `log_level` | ADMIN | NO_CONDITION | `src/xrpld/rpc/handlers/LogLevel.cpp:34` | 1-3 | STATE | http_forbidden (http_403_forbidden) |
| `logrotate` | ADMIN | NO_CONDITION | `src/xrpld/rpc/handlers/LogRotate.cpp:29` | 1-3 | STATE | http_forbidden (http_403_forbidden) |
| `manifest` | USER | NO_CONDITION | `src/xrpld/rpc/handlers/DoManifest.cpp:30` | 1-3 | PUBKEY_OUT | success () |
| `nft_buy_offers` | USER | NO_CONDITION | `src/xrpld/rpc/handlers/NFTOffers.cpp:165` | 1-3 | SAFE | rpc_error (objectNotFound) |
| `nft_sell_offers` | USER | NO_CONDITION | `src/xrpld/rpc/handlers/NFTOffers.cpp:151` | 1-3 | SAFE | rpc_error (objectNotFound) |
| `noripple_check` | USER | NO_CONDITION | `src/xrpld/rpc/handlers/NoRippleCheck.cpp:62` | 1-3 | SAFE | success () |
| `owner_info` | USER | NEEDS_CURRENT_LEDGER | `src/xrpld/rpc/handlers/OwnerInfo.cpp:35` | 1-3 | SAFE | success () |
| `peers` | ADMIN | NO_CONDITION | `src/xrpld/rpc/handlers/Peers.cpp:33` | 1-3 | STATE | http_forbidden (http_403_forbidden) |
| `path_find` | USER | NEEDS_CURRENT_LEDGER | `src/xrpld/rpc/handlers/PathFind.cpp:33` | 1-3 | SAFE | rpc_error (noEvents) |
| `ping` | USER | NO_CONDITION | `src/xrpld/rpc/handlers/Ping.cpp:33` | 1-3 | SAFE | success () |
| `print` | ADMIN | NO_CONDITION | `src/xrpld/rpc/handlers/Print.cpp:30` | 1-3 | STATE | http_forbidden (http_403_forbidden) |
| `random` | USER | NO_CONDITION | `src/xrpld/rpc/handlers/Random.cpp:39` | 1-3 | SAFE | success () |
| `peer_reservations_add` | ADMIN | NO_CONDITION | `src/xrpld/rpc/handlers/Reservations.cpp:36` | 1-3 | STATE | http_forbidden (http_403_forbidden) |
| `peer_reservations_del` | ADMIN | NO_CONDITION | `src/xrpld/rpc/handlers/Reservations.cpp:89` | 1-3 | STATE | http_forbidden (http_403_forbidden) |
| `peer_reservations_list` | ADMIN | NO_CONDITION | `src/xrpld/rpc/handlers/Reservations.cpp:116` | 1-3 | STATE | http_forbidden (http_403_forbidden) |
| `ripple_path_find` | USER | NO_CONDITION | `src/xrpld/rpc/handlers/RipplePathFind.cpp:33` | 1-3 | SAFE | success () |
| `server_definitions` | USER | NO_CONDITION | `src/xrpld/rpc/handlers/ServerInfo.cpp:299` | 1-3 | SAFE | success () |
| `server_info` | USER | NO_CONDITION | `src/xrpld/rpc/handlers/ServerInfo.cpp:322` | 1-3 | PUBKEY_OUT | success () |
| `server_state` | USER | NO_CONDITION | `src/xrpld/rpc/handlers/ServerState.cpp:30` | 1-3 | PUBKEY_OUT | success () |
| `sign` | USER | NO_CONDITION | `src/xrpld/rpc/handlers/SignHandler.cpp:34` | 1-3 | SECRET_IN|SIG_OUT | rpc_error (notSupported) |
| `sign_for` | USER | NO_CONDITION | `src/xrpld/rpc/handlers/SignFor.cpp:35` | 1-3 | SECRET_IN|SIG_OUT | rpc_error (notSupported) |
| `simulate` | USER | NEEDS_CURRENT_LEDGER | `src/xrpld/rpc/handlers/Simulate.cpp:311` | 1-3 | SAFE | rpc_error (invalidParams) |
| `stop` | ADMIN | NO_CONDITION | `src/xrpld/rpc/handlers/Stop.cpp:32` | 1-3 | STATE | http_forbidden (http_403_forbidden) |
| `submit` | USER | NEEDS_CURRENT_LEDGER | `src/xrpld/rpc/handlers/Submit.cpp:45` | 1-3 | SECRET_IN|SIG_RELAY | rpc_error (notSupported) |
| `submit_multisigned` | USER | NEEDS_CURRENT_LEDGER | `src/xrpld/rpc/handlers/SubmitMultiSigned.cpp:34` | 1-3 | SIG_RELAY | rpc_error (invalidParams) |
| `transaction_entry` | USER | NO_CONDITION | `src/xrpld/rpc/handlers/TransactionEntry.cpp:38` | 1-3 | PUBKEY_OUT | success () |
| `tx` | USER | NEEDS_NETWORK_CONNECTION | `src/xrpld/rpc/handlers/Tx.cpp:286` | 1-3 | PUBKEY_OUT | success () |
| `tx_history` | USER | NO_CONDITION | `src/xrpld/rpc/handlers/TxHistory.cpp:39` | 1 | PUBKEY_OUT | rpc_error (invalidParams) |
| `tx_reduce_relay` | USER | NO_CONDITION | `src/xrpld/rpc/handlers/TxReduceRelay.cpp:29` | 1-3 | SAFE | success () |
| `unl_list` | ADMIN | NO_CONDITION | `src/xrpld/rpc/handlers/UnlList.cpp:30` | 1-3 | PUBKEY_OUT | http_forbidden (http_403_forbidden) |
| `validation_create` | ADMIN | NO_CONDITION | `src/xrpld/rpc/handlers/ValidationCreate.cpp:45` | 1-3 | SECRET_IN|SECRET_OUT | http_forbidden (http_403_forbidden) |
| `validators` | ADMIN | NO_CONDITION | `src/xrpld/rpc/handlers/Validators.cpp:29` | 1-3 | PUBKEY_OUT | http_forbidden (http_403_forbidden) |
| `validator_list_sites` | ADMIN | NO_CONDITION | `src/xrpld/rpc/handlers/ValidatorListSites.cpp:29` | 1-3 | STATE | http_forbidden (http_403_forbidden) |
| `validator_info` | ADMIN | NO_CONDITION | `src/xrpld/rpc/handlers/ValidatorInfo.cpp:31` | 1-3 | PUBKEY_OUT | http_forbidden (http_403_forbidden) |
| `validator_votes` | USER | NO_CONDITION | `src/xrpld/rpc/handlers/ValidatorVotes.cpp:46` | 1-3 | PUBKEY_IN | rpc_error (invalidValidatorPublicKey) |
| `vault_info` | USER | NO_CONDITION | `src/xrpld/rpc/handlers/VaultInfo.cpp:79` | 1-3 | SAFE | rpc_error (malformedRequest) |
| `wallet_propose` | ADMIN | NO_CONDITION | `src/xrpld/rpc/handlers/WalletPropose.cpp:68` | 1-3 | SECRET_IN|SECRET_OUT | http_forbidden (http_403_forbidden) |
| `subscribe` | USER | NO_CONDITION | `src/xrpld/rpc/handlers/Subscribe.cpp:38` | 1-3 | PUBKEY_OUT | rpc_error (invalidParams) |
| `unsubscribe` | USER | NO_CONDITION | `src/xrpld/rpc/handlers/Unsubscribe.cpp:33` | 1-3 | SAFE | rpc_error (invalidParams) |
| `version` | USER | NO_CONDITION | `src/xrpld/rpc/handlers/Version.h:49` | 1-3 | SAFE | success () |

## Per-method parameters (summary)

- `account_info` — account, ledger_index, signer_lists, queue. account_data carries no key; signer_lists carry accounts and weights only
- `account_currencies` — account, ledger_index, strict. currency lists only
- `account_lines` — account, ledger_index, peer, limit, marker. trust lines only
- `account_channels` — account, destination_account, ledger_index, limit. channel ids, amounts, delays; no keys
- `account_nfts` — account, ledger_index, limit, marker. token ids and URIs; no keys
- `account_objects` — account, type, ledger_index, limit, marker. ledger entries; SignerList entries carry accounts only
- `account_offers` — account, ledger_index, limit, marker. offer amounts only
- `account_tx` — account, ledger_index_min/max, limit, marker, binary, forward. every returned transaction carries SigningPubKey and TxnSignature
- `amm_info` — asset, asset2, ledger_index. pool balances and LP tokens; no keys
- `blacklist` — threshold (ADMIN). ADMIN: peer blacklist control
- `book_changes` — taker_pays, taker_gets, ledger_index, limit. order-book deltas; no keys
- `book_offers` — taker_pays, taker_gets, ledger_index, limit, taker. offers; no keys
- `can_delete` — can_delete (ADMIN). ADMIN: reports ledgers that may be deleted
- `channel_authorize` — channel_id, amount, secret | key_type+seed. takes secret (or key_type+seed) and returns a channel-claim signature
- `channel_verify` — channel_id, amount, public_key, signature. takes public_key + signature and verifies the claim; does not sign
- `connect` — ip, port (ADMIN). ADMIN: connects to a peer by IP
- `consensus_info` — — (ADMIN). ADMIN: consensus state; no keys
- `deposit_authorized` — source_account, destination_account, ledger_index. boolean + ledger entry data; no keys
- `exclusion_info` — — (feature-gated: PF_AccountExclusion). excluded-account list; no keys
- `feature` — feature, vetoed. amendment list; no keys
- `fee` — —. fee levels; no keys
- `fetch_info` — clear (ADMIN). ADMIN: ledger-fetch state
- `gateway_balances` — account, hotwallet, ledger_index, strict. balances; no keys
- `get_counts` — min_count (ADMIN). ADMIN: internal counters
- `get_aggregate_price` — oracles, base, quote. oracle price; no keys
- `ledger` — ledger_index/hash, full, transactions, accounts, expand, owner_funds, binary, queue. conditional: transactions:true returns tx JSON with SigningPubKey and TxnSignature
- `ledger_accept` — — (ADMIN; standalone only). ADMIN: closes the ledger (standalone mode only)
- `ledger_cleaner` — max_ledger, min_ledger, ... (ADMIN). ADMIN: ledger cleaner control
- `ledger_closed` — —. ledger hash and index only
- `ledger_current` — —. ledger index only
- `ledger_data` — ledger_index/hash, limit, marker, binary. conditional: ltPAYCHAN entries carry sfPublicKey; other entries carry no key
- `ledger_entry` — index | account_root | ... (one entry selector). conditional: ltPAYCHAN entries carry sfPublicKey
- `ledger_header` — ledger_index/hash (API v1 only). header hash chain only; no signature, no key
- `ledger_request` — ledger_hash (ADMIN). ADMIN: requests a ledger from peers
- `log_level` — severity, partition (ADMIN). ADMIN: changes log verbosity
- `logrotate` — — (ADMIN). ADMIN: rotates log files
- `manifest` — public_key. returns the manifest for a public key: signing key plus master signature
- `nft_buy_offers` — nft_id, ledger_index, limit. offer amounts; no keys
- `nft_sell_offers` — nft_id, ledger_index, limit. offer amounts; no keys
- `noripple_check` — account, role, transactions, limit. account flags; no keys
- `owner_info` — account, ledger_index. owned objects; no keys
- `peers` — — (ADMIN). ADMIN: peer list (IPs, versions); no keys in the handler
- `path_find` — subcommand create/close/status + path params (WS-only). paths and alternatives; no keys
- `ping` — —. liveness only
- `print` — — (ADMIN). ADMIN: prints internal state to the log
- `random` — —. 256-bit CSPRNG output; not key material
- `peer_reservations_add` — public_key, description (ADMIN). ADMIN: peer reservation control
- `peer_reservations_del` — public_key (ADMIN). ADMIN: peer reservation control
- `peer_reservations_list` — — (ADMIN). ADMIN: peer reservation list
- `ripple_path_find` — source_account, destination_account, destination_amount (IOU), ledger_index. paths and alternatives; no keys
- `server_definitions` — —. field and type definitions; no keys
- `server_info` — —. returns pubkey_node (the node's secp256k1 validator public key) plus listening ports
- `server_state` — —. returns state.pubkey_node (the node's secp256k1 validator public key)
- `sign` — tx_json, secret | seed | seed_hex | passphrase, key_type, offline, fee_mult_max, .... takes exactly one of passphrase/secret/seed/seed_hex and returns a signed tx_blob/tx_json
- `sign_for` — tx_json, account, secret | seed | ..., key_type. takes exactly one of passphrase/secret/seed/seed_hex and returns a multi-signed tx
- `simulate` — tx_blob | tx_json. dry-runs a supplied tx_json; echoes any SigningPubKey/TxnSignature already in it, signs nothing
- `stop` — — (ADMIN). ADMIN: stops the server
- `submit` — tx_blob XOR tx_json (+secret when signing, deprecated). tx_blob path relays a pre-signed transaction; tx_json+secret path signs server-side when signing is enabled (deprecated)
- `submit_multisigned` — tx_json (fully multi-signed). relays a fully multi-signed transaction; no signing
- `transaction_entry` — tx_hash, ledger_index/hash. returns tx JSON with SigningPubKey and TxnSignature
- `tx` — transaction (hash or ctid), binary, min_ledger, max_ledger. returns tx JSON with SigningPubKey and TxnSignature
- `tx_history` — start (API v1 only). returns transaction history JSON with SigningPubKey and TxnSignature
- `tx_reduce_relay` — —. overlay transaction metrics; no keys
- `unl_list` — — (ADMIN). ADMIN: returns the UNL with validator public keys (pubkey_validator)
- `validation_create` — secret (optional) (ADMIN). ADMIN: optional secret input; returns validation_seed and validation_key
- `validators` — — (ADMIN). ADMIN: returns validator lists with publisher public keys (pubkey_publisher)
- `validator_list_sites` — — (ADMIN). ADMIN: validator site list; no keys
- `validator_info` — — (ADMIN). ADMIN: returns this node's ephemeral validation public key
- `validator_votes` — validation_public_key. takes validation_public_key and returns that validator's amendment votes
- `vault_info` — vault_id | owner+seq. vault entry data; no keys
- `wallet_propose` — passphrase | seed | seed_hex, key_type (optional) (ADMIN). ADMIN: optional passphrase/seed input; returns master_seed, master_key and account
- `subscribe` — streams[], accounts[], books[] (WS-only). live streams: validations carry validator pubkeys and signatures, transactions carry SigningPubKey
- `unsubscribe` — streams[], accounts[], books[] (WS-only). cancels subscriptions
- `version` — —. build version string only

## gRPC methods (code-derived, not probed live)

The gRPC server (`src/xrpld/app/main/GRPCServer.cpp`) listens with
`InsecureServerCredentials()` — no authentication mechanism
(`GRPCServer.cpp:568-575`) — and assigns roles `IDENTIFIED` or `USER`
only (`GRPCServer.cpp:232-238`); no ADMIN role exists on gRPC. All
four methods are read-only ledger reads:

| Method | Handler |
|---|---|
| `GetLedger` | `doLedgerGrpc` (`src/xrpld/rpc/GRPCHandlers.h`, `src/xrpld/rpc/handlers/LedgerHandler.cpp`) |
| `GetLedgerEntry` | `doLedgerEntryGrpc` (`src/xrpld/rpc/GRPCHandlers.h`, `src/xrpld/rpc/handlers/LedgerHandler.cpp`) |
| `GetLedgerData` | `doLedgerDataGrpc` (`src/xrpld/rpc/GRPCHandlers.h`, `src/xrpld/rpc/handlers/LedgerHandler.cpp`) |
| `GetLedgerDiff` | `doLedgerDiffGrpc` (`src/xrpld/rpc/GRPCHandlers.h`, `src/xrpld/rpc/handlers/LedgerDiff.cpp`) |

The public endpoint's gRPC port (50051, listed in `server_info`)
is not reachable from this machine, so none of these was probed
live (see `assumptions.md` A7).

## WebSocket subscription streams (code-derived, not probed live)

`subscribe` / `unsubscribe` are USER methods, but subscriptions
require a WebSocket connection (`Subscribe.cpp:116-167`). Streams:

| Stream | What it carries (quantum relevance) |
|---|---|
| `server` | Server status; no keys |
| `ledger` | Closed-ledger notifications; no keys |
| `book_changes` | Order-book deltas; no keys |
| `manifests` | Validator manifests as they arrive — signing keys plus master signatures |
| `transactions` | Validated transactions — SigningPubKey and TxnSignature, live |
| `transactions_proposed` | Proposed (unvalidated) transactions — SigningPubKey and TxnSignature, live |
| `rt_transactions` | Deprecated alias of `transactions_proposed` |
| `validations` | Live validator validations — validator public keys and signatures |
| `peer_status` | Peer connection events; no keys |
| `consensus` | Consensus phase changes; no keys |

`subscribe` over plain HTTP POST returns `invalidParams` (probed);
`path_find` (subcommand `create`) over HTTP returns `noEvents`
("Current transport does not support events", probed) — both need a
WebSocket. No WebSocket client is available in this harness, so the
streams were not probed live (see `assumptions.md` A7).

## TLS

The code's default TLS cipher list is
`TLSv1.2:!CBC:!DSS:!PSK:!eNULL:!aNULL`
(`src/libxrpl/basics/make_SSLContext.cpp:104`), overridable per port
with `ssl_ciphers` (`Port.cpp:327`). Whether the public endpoint
negotiates TLS 1.2 or 1.3, and with which cipher, is not observable
from this machine: the egress proxy terminates TLS and re-signs the
certificate (see `assumptions.md` A8).
