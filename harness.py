#!/usr/bin/env python3
"""Post-quantum RPC and API surface security assessment: probe harness.

Probes the public, read-only PFTL testnet JSON-RPC endpoint
(https://rpc.testnet.postfiat.org/) with read-only or empty-parameter
calls only (no credentials, no secrets, no writes, no live peer
connections) and quantifies which API methods expose key material,
signatures, or signing capability, and which are gated to ADMIN.

Two modes:
  * --live    : probe the endpoint and write results/probe_raw.json
                (the vendored raw sample) plus all derived outputs.
  * --offline : (default) regenerate every derived output from the
                vendored results/probe_raw.json, with no network
                access. This is the reproducible path used by run_all.sh.

The method inventory (74 JSON-RPC methods) is embedded below as
METHOD_TABLE, transcribed from the pinned tree's handler table
(src/xrpld/rpc/detail/Handler.cpp) plus the two new-style handlers
(LedgerHandler, VersionHandler). When the pinned tree is available,
the harness re-parses Handler.cpp and cross-checks the embedded table
against it; any mismatch is recorded in results/summary.json
(tree_table_matches_embedded) rather than silently accepted.

Usage:
    python3 harness.py --live    [--out-dir results] [--tree <postfiatd tree>]
    python3 harness.py           [--out-dir results] [--tree <postfiatd tree>]

Python 3.8+ standard library only.
"""

import argparse
import csv
import hashlib
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

HARNESS_VERSION = "1.0.0"
RPC_ENDPOINT = "https://rpc.testnet.postfiat.org/"
PINNED_COMMIT = "0085a1ff885d6a446369cf73a4430f75af22be55"

# Public testnet account used as a probe subject (the account is public
# ledger data; no secret or credential is involved). It is the account
# that transacted in the companion historical-ledger pack's sample.
PROBE_ACCOUNT = "rHFd9HgQXaegmSj5oudYEtxspC23xKuJ5z"
# One validated transaction hash from the public ledger (NFTokenMint,
# ledger 8020944), used as a read-only probe subject for tx /
# transaction_entry. It is public ledger data.
PROBE_TX_HASH = "26A1A21211FA1FD1D7B41259A3A17E860D438FA00609052BFC20F0825BA7BE11"
PROBE_TX_LEDGER = 8020944
# A second public account (the NFTokenMint account from the companion
# pack's public sample), used only as a path-finding destination.
PROBE_OTHER_ACCOUNT = "rLSzVyyjZBjWKVyLAp97123tiuVZvVJDfq"

MAX_TRIES = 3
DEFAULT_TIMEOUT = 25
LONG_TIMEOUT = 40
# Responses larger than this are stored truncated (head + digest + keys).
STORE_CAP_BYTES = 32768

# Keys whose values must never be stored in the pack, even if a server
# unexpectedly returns them (e.g. if an ADMIN gate were misconfigured
# and wallet_propose / validation_create returned generated secrets).
SENSITIVE_KEYS = {
    "secret", "seed", "seed_hex", "master_seed", "validation_seed",
    "passphrase", "private_key", "admin_password", "admin_user",
    "password",
}

# ---------------------------------------------------------------------------
# Method inventory, transcribed from the pinned tree.
# Columns: method, role, condition, handler file, handler line, api range.
# Handler lines are the line of the doXxx function definition, except
# for the two new-style handlers where the line is the `name` constant.
# ---------------------------------------------------------------------------
METHOD_TABLE = [
    ("account_info", "USER", "NO_CONDITION", "src/xrpld/rpc/handlers/AccountInfo.cpp", 50, "1-3"),
    ("account_currencies", "USER", "NO_CONDITION", "src/xrpld/rpc/handlers/AccountCurrenciesHandler.cpp", 32, "1-3"),
    ("account_lines", "USER", "NO_CONDITION", "src/xrpld/rpc/handlers/AccountLines.cpp", 81, "1-3"),
    ("account_channels", "USER", "NO_CONDITION", "src/xrpld/rpc/handlers/AccountChannels.cpp", 68, "1-3"),
    ("account_nfts", "USER", "NO_CONDITION", "src/xrpld/rpc/handlers/AccountObjects.cpp", 50, "1-3"),
    ("account_objects", "USER", "NO_CONDITION", "src/xrpld/rpc/handlers/AccountObjects.cpp", 181, "1-3"),
    ("account_offers", "USER", "NO_CONDITION", "src/xrpld/rpc/handlers/AccountOffers.cpp", 57, "1-3"),
    ("account_tx", "USER", "NO_CONDITION", "src/xrpld/rpc/handlers/AccountTx.cpp", 408, "1-3"),
    ("amm_info", "USER", "NO_CONDITION", "src/xrpld/rpc/handlers/AMMInfo.cpp", 76, "1-3"),
    ("blacklist", "ADMIN", "NO_CONDITION", "src/xrpld/rpc/handlers/BlackList.cpp", 29, "1-3"),
    ("book_changes", "USER", "NO_CONDITION", "src/xrpld/rpc/handlers/BookOffers.cpp", 222, "1-3"),
    ("book_offers", "USER", "NO_CONDITION", "src/xrpld/rpc/handlers/BookOffers.cpp", 37, "1-3"),
    ("can_delete", "ADMIN", "NO_CONDITION", "src/xrpld/rpc/handlers/CanDelete.cpp", 35, "1-3"),
    ("channel_authorize", "USER", "NO_CONDITION", "src/xrpld/rpc/handlers/PayChanClaim.cpp", 42, "1-3"),
    ("channel_verify", "USER", "NO_CONDITION", "src/xrpld/rpc/handlers/PayChanClaim.cpp", 113, "1-3"),
    ("connect", "ADMIN", "NO_CONDITION", "src/xrpld/rpc/handlers/Connect.cpp", 39, "1-3"),
    ("consensus_info", "ADMIN", "NO_CONDITION", "src/xrpld/rpc/handlers/ConsensusInfo.cpp", 30, "1-3"),
    ("deposit_authorized", "USER", "NO_CONDITION", "src/xrpld/rpc/handlers/DepositAuthorized.cpp", 41, "1-3"),
    ("exclusion_info", "USER", "NO_CONDITION", "src/xrpld/rpc/handlers/ExclusionInfo.cpp", 35, "1-3"),
    ("feature", "USER", "NO_CONDITION", "src/xrpld/rpc/handlers/Feature1.cpp", 36, "1-3"),
    ("fee", "USER", "NEEDS_CURRENT_LEDGER", "src/xrpld/rpc/handlers/Fee1.cpp", 30, "1-3"),
    ("fetch_info", "ADMIN", "NO_CONDITION", "src/xrpld/rpc/handlers/FetchInfo.cpp", 30, "1-3"),
    ("gateway_balances", "USER", "NO_CONDITION", "src/xrpld/rpc/handlers/GatewayBalances.cpp", 54, "1-3"),
    ("get_counts", "ADMIN", "NO_CONDITION", "src/xrpld/rpc/handlers/GetCounts.cpp", 138, "1-3"),
    ("get_aggregate_price", "USER", "NO_CONDITION", "src/xrpld/rpc/handlers/GetAggregatePrice.cpp", 153, "1-3"),
    ("ledger", "USER", "NO_CONDITION", "src/xrpld/rpc/handlers/LedgerHandler.h", 63, "1-3"),
    ("ledger_accept", "ADMIN", "NEEDS_CURRENT_LEDGER", "src/xrpld/rpc/handlers/LedgerAccept.cpp", 34, "1-3"),
    ("ledger_cleaner", "ADMIN", "NEEDS_NETWORK_CONNECTION", "src/xrpld/rpc/handlers/LedgerCleanerHandler.cpp", 30, "1-3"),
    ("ledger_closed", "USER", "NEEDS_CLOSED_LEDGER", "src/xrpld/rpc/handlers/LedgerClosed.cpp", 30, "1-3"),
    ("ledger_current", "USER", "NEEDS_CURRENT_LEDGER", "src/xrpld/rpc/handlers/LedgerCurrent.cpp", 30, "1-3"),
    ("ledger_data", "USER", "NO_CONDITION", "src/xrpld/rpc/handlers/LedgerData.cpp", 46, "1-3"),
    ("ledger_entry", "USER", "NO_CONDITION", "src/xrpld/rpc/handlers/LedgerEntry.cpp", 755, "1-3"),
    ("ledger_header", "USER", "NO_CONDITION", "src/xrpld/rpc/handlers/LedgerHeader.cpp", 34, "1"),
    ("ledger_request", "ADMIN", "NO_CONDITION", "src/xrpld/rpc/handlers/LedgerRequest.cpp", 36, "1-3"),
    ("log_level", "ADMIN", "NO_CONDITION", "src/xrpld/rpc/handlers/LogLevel.cpp", 34, "1-3"),
    ("logrotate", "ADMIN", "NO_CONDITION", "src/xrpld/rpc/handlers/LogRotate.cpp", 29, "1-3"),
    ("manifest", "USER", "NO_CONDITION", "src/xrpld/rpc/handlers/DoManifest.cpp", 30, "1-3"),
    ("nft_buy_offers", "USER", "NO_CONDITION", "src/xrpld/rpc/handlers/NFTOffers.cpp", 165, "1-3"),
    ("nft_sell_offers", "USER", "NO_CONDITION", "src/xrpld/rpc/handlers/NFTOffers.cpp", 151, "1-3"),
    ("noripple_check", "USER", "NO_CONDITION", "src/xrpld/rpc/handlers/NoRippleCheck.cpp", 62, "1-3"),
    ("owner_info", "USER", "NEEDS_CURRENT_LEDGER", "src/xrpld/rpc/handlers/OwnerInfo.cpp", 35, "1-3"),
    ("peers", "ADMIN", "NO_CONDITION", "src/xrpld/rpc/handlers/Peers.cpp", 33, "1-3"),
    ("path_find", "USER", "NEEDS_CURRENT_LEDGER", "src/xrpld/rpc/handlers/PathFind.cpp", 33, "1-3"),
    ("ping", "USER", "NO_CONDITION", "src/xrpld/rpc/handlers/Ping.cpp", 33, "1-3"),
    ("print", "ADMIN", "NO_CONDITION", "src/xrpld/rpc/handlers/Print.cpp", 30, "1-3"),
    ("random", "USER", "NO_CONDITION", "src/xrpld/rpc/handlers/Random.cpp", 39, "1-3"),
    ("peer_reservations_add", "ADMIN", "NO_CONDITION", "src/xrpld/rpc/handlers/Reservations.cpp", 36, "1-3"),
    ("peer_reservations_del", "ADMIN", "NO_CONDITION", "src/xrpld/rpc/handlers/Reservations.cpp", 89, "1-3"),
    ("peer_reservations_list", "ADMIN", "NO_CONDITION", "src/xrpld/rpc/handlers/Reservations.cpp", 116, "1-3"),
    ("ripple_path_find", "USER", "NO_CONDITION", "src/xrpld/rpc/handlers/RipplePathFind.cpp", 33, "1-3"),
    ("server_definitions", "USER", "NO_CONDITION", "src/xrpld/rpc/handlers/ServerInfo.cpp", 299, "1-3"),
    ("server_info", "USER", "NO_CONDITION", "src/xrpld/rpc/handlers/ServerInfo.cpp", 322, "1-3"),
    ("server_state", "USER", "NO_CONDITION", "src/xrpld/rpc/handlers/ServerState.cpp", 30, "1-3"),
    ("sign", "USER", "NO_CONDITION", "src/xrpld/rpc/handlers/SignHandler.cpp", 34, "1-3"),
    ("sign_for", "USER", "NO_CONDITION", "src/xrpld/rpc/handlers/SignFor.cpp", 35, "1-3"),
    ("simulate", "USER", "NEEDS_CURRENT_LEDGER", "src/xrpld/rpc/handlers/Simulate.cpp", 311, "1-3"),
    ("stop", "ADMIN", "NO_CONDITION", "src/xrpld/rpc/handlers/Stop.cpp", 32, "1-3"),
    ("submit", "USER", "NEEDS_CURRENT_LEDGER", "src/xrpld/rpc/handlers/Submit.cpp", 45, "1-3"),
    ("submit_multisigned", "USER", "NEEDS_CURRENT_LEDGER", "src/xrpld/rpc/handlers/SubmitMultiSigned.cpp", 34, "1-3"),
    ("transaction_entry", "USER", "NO_CONDITION", "src/xrpld/rpc/handlers/TransactionEntry.cpp", 38, "1-3"),
    ("tx", "USER", "NEEDS_NETWORK_CONNECTION", "src/xrpld/rpc/handlers/Tx.cpp", 286, "1-3"),
    ("tx_history", "USER", "NO_CONDITION", "src/xrpld/rpc/handlers/TxHistory.cpp", 39, "1"),
    ("tx_reduce_relay", "USER", "NO_CONDITION", "src/xrpld/rpc/handlers/TxReduceRelay.cpp", 29, "1-3"),
    ("unl_list", "ADMIN", "NO_CONDITION", "src/xrpld/rpc/handlers/UnlList.cpp", 30, "1-3"),
    ("validation_create", "ADMIN", "NO_CONDITION", "src/xrpld/rpc/handlers/ValidationCreate.cpp", 45, "1-3"),
    ("validators", "ADMIN", "NO_CONDITION", "src/xrpld/rpc/handlers/Validators.cpp", 29, "1-3"),
    ("validator_list_sites", "ADMIN", "NO_CONDITION", "src/xrpld/rpc/handlers/ValidatorListSites.cpp", 29, "1-3"),
    ("validator_info", "ADMIN", "NO_CONDITION", "src/xrpld/rpc/handlers/ValidatorInfo.cpp", 31, "1-3"),
    ("validator_votes", "USER", "NO_CONDITION", "src/xrpld/rpc/handlers/ValidatorVotes.cpp", 46, "1-3"),
    ("vault_info", "USER", "NO_CONDITION", "src/xrpld/rpc/handlers/VaultInfo.cpp", 79, "1-3"),
    ("wallet_propose", "ADMIN", "NO_CONDITION", "src/xrpld/rpc/handlers/WalletPropose.cpp", 68, "1-3"),
    ("subscribe", "USER", "NO_CONDITION", "src/xrpld/rpc/handlers/Subscribe.cpp", 38, "1-3"),
    ("unsubscribe", "USER", "NO_CONDITION", "src/xrpld/rpc/handlers/Unsubscribe.cpp", 33, "1-3"),
    ("version", "USER", "NO_CONDITION", "src/xrpld/rpc/handlers/Version.h", 49, "1-3"),
]

# Exposure classes (key-material handling per method, from reading the
# handler code cited in api_inventory.md):
#   SAFE       no key material in request or response
#   PUBKEY_OUT returns public keys and/or signed data (harvest surface)
#   PUBKEY_IN  takes a public key as input (lookup by key)
#   SECRET_IN  accepts a secret/seed/passphrase in the request body
#   SECRET_OUT generates or returns secret material
#   SIG_OUT    produces a signature (signing entry point)
#   SIG_VERIFY verifies a supplied signature against a supplied key
#   SIG_RELAY  relays a pre-signed transaction (no signing)
#   STATE      privileged control operation, no key material
EXPOSURE = {
    "account_info": ("SAFE", "account_data carries no key; signer_lists carry accounts and weights only"),
    "account_currencies": ("SAFE", "currency lists only"),
    "account_lines": ("SAFE", "trust lines only"),
    "account_channels": ("SAFE", "channel ids, amounts, delays; no keys"),
    "account_nfts": ("SAFE", "token ids and URIs; no keys"),
    "account_objects": ("SAFE", "ledger entries; SignerList entries carry accounts only"),
    "account_offers": ("SAFE", "offer amounts only"),
    "account_tx": ("PUBKEY_OUT", "every returned transaction carries SigningPubKey and TxnSignature"),
    "amm_info": ("SAFE", "pool balances and LP tokens; no keys"),
    "blacklist": ("STATE", "ADMIN: peer blacklist control"),
    "book_changes": ("SAFE", "order-book deltas; no keys"),
    "book_offers": ("SAFE", "offers; no keys"),
    "can_delete": ("STATE", "ADMIN: reports ledgers that may be deleted"),
    "channel_authorize": ("SECRET_IN|SIG_OUT", "takes secret (or key_type+seed) and returns a channel-claim signature"),
    "channel_verify": ("SIG_VERIFY", "takes public_key + signature and verifies the claim; does not sign"),
    "connect": ("STATE", "ADMIN: connects to a peer by IP"),
    "consensus_info": ("STATE", "ADMIN: consensus state; no keys"),
    "deposit_authorized": ("SAFE", "boolean + ledger entry data; no keys"),
    "exclusion_info": ("SAFE", "excluded-account list; no keys"),
    "feature": ("SAFE", "amendment list; no keys"),
    "fee": ("SAFE", "fee levels; no keys"),
    "fetch_info": ("STATE", "ADMIN: ledger-fetch state"),
    "gateway_balances": ("SAFE", "balances; no keys"),
    "get_counts": ("STATE", "ADMIN: internal counters"),
    "get_aggregate_price": ("SAFE", "oracle price; no keys"),
    "ledger": ("PUBKEY_OUT", "conditional: transactions:true returns tx JSON with SigningPubKey and TxnSignature"),
    "ledger_accept": ("STATE", "ADMIN: closes the ledger (standalone mode only)"),
    "ledger_cleaner": ("STATE", "ADMIN: ledger cleaner control"),
    "ledger_closed": ("SAFE", "ledger hash and index only"),
    "ledger_current": ("SAFE", "ledger index only"),
    "ledger_data": ("PUBKEY_OUT", "conditional: ltPAYCHAN entries carry sfPublicKey; other entries carry no key"),
    "ledger_entry": ("PUBKEY_OUT", "conditional: ltPAYCHAN entries carry sfPublicKey"),
    "ledger_header": ("SAFE", "header hash chain only; no signature, no key"),
    "ledger_request": ("STATE", "ADMIN: requests a ledger from peers"),
    "log_level": ("STATE", "ADMIN: changes log verbosity"),
    "logrotate": ("STATE", "ADMIN: rotates log files"),
    "manifest": ("PUBKEY_OUT", "returns the manifest for a public key: signing key plus master signature"),
    "nft_buy_offers": ("SAFE", "offer amounts; no keys"),
    "nft_sell_offers": ("SAFE", "offer amounts; no keys"),
    "noripple_check": ("SAFE", "account flags; no keys"),
    "owner_info": ("SAFE", "owned objects; no keys"),
    "peers": ("STATE", "ADMIN: peer list (IPs, versions); no keys in the handler"),
    "path_find": ("SAFE", "paths and alternatives; no keys"),
    "ping": ("SAFE", "liveness only"),
    "print": ("STATE", "ADMIN: prints internal state to the log"),
    "random": ("SAFE", "256-bit CSPRNG output; not key material"),
    "peer_reservations_add": ("STATE", "ADMIN: peer reservation control"),
    "peer_reservations_del": ("STATE", "ADMIN: peer reservation control"),
    "peer_reservations_list": ("STATE", "ADMIN: peer reservation list"),
    "ripple_path_find": ("SAFE", "paths and alternatives; no keys"),
    "server_definitions": ("SAFE", "field and type definitions; no keys"),
    "server_info": ("PUBKEY_OUT", "returns pubkey_node (the node's secp256k1 validator public key) plus listening ports"),
    "server_state": ("PUBKEY_OUT", "returns state.pubkey_node (the node's secp256k1 validator public key)"),
    "sign": ("SECRET_IN|SIG_OUT", "takes exactly one of passphrase/secret/seed/seed_hex and returns a signed tx_blob/tx_json"),
    "sign_for": ("SECRET_IN|SIG_OUT", "takes exactly one of passphrase/secret/seed/seed_hex and returns a multi-signed tx"),
    "simulate": ("SAFE", "dry-runs a supplied tx_json; echoes any SigningPubKey/TxnSignature already in it, signs nothing"),
    "stop": ("STATE", "ADMIN: stops the server"),
    "submit": ("SECRET_IN|SIG_RELAY", "tx_blob path relays a pre-signed transaction; tx_json+secret path signs server-side when signing is enabled (deprecated)"),
    "submit_multisigned": ("SIG_RELAY", "relays a fully multi-signed transaction; no signing"),
    "transaction_entry": ("PUBKEY_OUT", "returns tx JSON with SigningPubKey and TxnSignature"),
    "tx": ("PUBKEY_OUT", "returns tx JSON with SigningPubKey and TxnSignature"),
    "tx_history": ("PUBKEY_OUT", "returns transaction history JSON with SigningPubKey and TxnSignature"),
    "tx_reduce_relay": ("SAFE", "overlay transaction metrics; no keys"),
    "unl_list": ("PUBKEY_OUT", "ADMIN: returns the UNL with validator public keys (pubkey_validator)"),
    "validation_create": ("SECRET_IN|SECRET_OUT", "ADMIN: optional secret input; returns validation_seed and validation_key"),
    "validators": ("PUBKEY_OUT", "ADMIN: returns validator lists with publisher public keys (pubkey_publisher)"),
    "validator_list_sites": ("STATE", "ADMIN: validator site list; no keys"),
    "validator_info": ("PUBKEY_OUT", "ADMIN: returns this node's ephemeral validation public key"),
    "validator_votes": ("PUBKEY_IN", "takes validation_public_key and returns that validator's amendment votes"),
    "vault_info": ("SAFE", "vault entry data; no keys"),
    "wallet_propose": ("SECRET_IN|SECRET_OUT", "ADMIN: optional passphrase/seed input; returns master_seed, master_key and account"),
    "subscribe": ("PUBKEY_OUT", "live streams: validations carry validator pubkeys and signatures, transactions carry SigningPubKey"),
    "unsubscribe": ("SAFE", "cancels subscriptions"),
    "version": ("SAFE", "build version string only"),
}

# gRPC surface (code-derived only; the public endpoint's gRPC port is
# not reachable from this machine — see assumptions.md).
GRPC_METHODS = [
    ("GetLedger", "src/xrpld/rpc/GRPCHandlers.h", "doLedgerGrpc"),
    ("GetLedgerEntry", "src/xrpld/rpc/GRPCHandlers.h", "doLedgerEntryGrpc"),
    ("GetLedgerData", "src/xrpld/rpc/GRPCHandlers.h", "doLedgerDataGrpc"),
    ("GetLedgerDiff", "src/xrpld/rpc/GRPCHandlers.h", "doLedgerDiffGrpc"),
]

# WebSocket subscription streams (code-derived only; no WebSocket client
# is available in this harness — see assumptions.md).
WS_STREAMS = [
    "server", "ledger", "book_changes", "manifests", "transactions",
    "transactions_proposed", "rt_transactions", "validations",
    "peer_status", "consensus",
]


def utcnow_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def redact(obj):
    """Recursively replace values of sensitive keys. Returns (new, count)."""
    count = [0]

    def walk(o):
        if isinstance(o, dict):
            out = {}
            for k, v in o.items():
                if k in SENSITIVE_KEYS:
                    count[0] += 1
                    out[k] = "<redacted>"
                else:
                    out[k] = walk(v)
            return out
        if isinstance(o, list):
            return [walk(x) for x in o]
        return o

    return walk(obj), count[0]


def rpc_call(method, params, timeout=DEFAULT_TIMEOUT):
    """One JSON-RPC call.

    Returns (payload_or_None, http_status_or_None, error_str_or_None,
    attempts, duration_ms). A JSON error envelope is a payload, not a
    transport error. An HTTP 403 from the gateway/node HTTP layer (plain
    text body "Forbidden") is reported via http_status so the caller can
    distinguish the HTTP-layer refusal from the JSON-RPC layer.
    """
    body = json.dumps({"method": method, "params": params}).encode()
    last_err = None
    for attempt in range(1, MAX_TRIES + 1):
        try:
            req = urllib.request.Request(
                RPC_ENDPOINT, data=body,
                headers={"Content-Type": "application/json"},
                method="POST")
            t0 = time.time()
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                payload = json.load(resp)
            dt_ms = int((time.time() - t0) * 1000)
            return payload, resp.status, None, attempt, dt_ms
        except urllib.error.HTTPError as exc:
            # The HTTP layer refused (e.g. 403 Forbidden for ADMIN
            # methods). Read the body: it may be JSON or plain text.
            try:
                raw = exc.read().decode("utf-8", "replace")
            except Exception:  # noqa: BLE001
                raw = ""
            try:
                payload = json.loads(raw)
            except ValueError:
                payload = None
            dt_ms = None
            if payload is not None:
                return payload, exc.code, None, attempt, dt_ms
            return ({"_http_error": {"status": exc.code, "body": raw}},
                    exc.code, None, attempt, dt_ms)
        except Exception as exc:  # noqa: BLE001 - record and retry everything
            last_err = "%s: %s" % (type(exc).__name__, exc)
            time.sleep(1.5 * attempt)
    return None, None, "failed_after_%d_tries: %s" % (MAX_TRIES, last_err), MAX_TRIES, None


def probe_params(method, ctx):
    """Params for one probe. Never includes a secret, seed or passphrase."""
    acct = PROBE_ACCOUNT
    txh = PROBE_TX_HASH
    xrp = {"currency": "XRP"}
    if method == "server_info":
        return [{}], 2, DEFAULT_TIMEOUT
    if method == "ledger":
        return [{"ledger_index": "validated", "transactions": False,
                 "expand": False, "owner_funds": False}], 2, DEFAULT_TIMEOUT
    if method == "ledger_data":
        return [{"ledger_index": "validated", "limit": 5}], 2, DEFAULT_TIMEOUT
    if method == "ledger_entry":
        return [{"ledger_index": "validated", "account_root": acct}], 2, DEFAULT_TIMEOUT
    if method == "ledger_header":
        return [{"ledger_index": "validated"}], 1, DEFAULT_TIMEOUT
    if method == "account_info":
        return [{"account": acct, "ledger_index": "validated"}], 2, DEFAULT_TIMEOUT
    if method in ("account_currencies", "account_lines", "account_channels",
                  "account_objects", "account_offers", "account_nfts"):
        p = {"account": acct}
        if method in ("account_objects", "account_nfts"):
            p["limit"] = 5
        return [p], 2, DEFAULT_TIMEOUT
    if method == "account_tx":
        return [{"account": acct, "ledger_index_min": -1,
                 "ledger_index_max": -1, "limit": 5}], 2, DEFAULT_TIMEOUT
    if method == "amm_info":
        return [{}], 2, DEFAULT_TIMEOUT
    if method in ("book_offers", "book_changes"):
        return [{"taker_pays": xrp, "taker_gets": xrp, "limit": 1}], 2, DEFAULT_TIMEOUT
    if method in ("channel_authorize", "channel_verify", "sign", "sign_for",
                  "submit", "submit_multisigned", "simulate"):
        return [{}], 2, DEFAULT_TIMEOUT
    if method == "deposit_authorized":
        return [{"source_account": acct, "destination_account": acct}], 2, DEFAULT_TIMEOUT
    if method == "gateway_balances":
        return [{"account": acct, "hotwallet": [acct]}], 2, DEFAULT_TIMEOUT
    if method == "manifest":
        return [{"public_key": ctx.get("pubkey_node", "")}], 2, DEFAULT_TIMEOUT
    if method in ("nft_buy_offers", "nft_sell_offers"):
        tokenid = ctx.get("tokenid")
        if tokenid:
            return [{"nft_id": tokenid}], 2, DEFAULT_TIMEOUT
        return [{}], 2, DEFAULT_TIMEOUT
    if method == "noripple_check":
        return [{"account": acct, "role": "gateway", "transactions": False,
                 "limit": 2}], 2, DEFAULT_TIMEOUT
    if method == "owner_info":
        return [{"account": acct}], 2, DEFAULT_TIMEOUT
    if method == "path_find":
        # subcommand create over HTTP: the handler requires a
        # subscription context, so the honest outcome is noEvents.
        return [{"subcommand": "create", "source_account": acct,
                 "destination_account": PROBE_OTHER_ACCOUNT,
                 "destination_amount": {"currency": "USD", "issuer": acct,
                                        "value": "1"}}], 2, LONG_TIMEOUT
    if method == "ripple_path_find":
        # Legacy pathfinder rejects XRP destination amounts
        # (dstAmtMalformed); an IOU destination amount works.
        return [{"source_account": acct,
                 "destination_account": PROBE_OTHER_ACCOUNT,
                 "destination_amount": {"currency": "USD", "issuer": acct,
                                        "value": "1"},
                 "ledger_index": "validated"}], 2, LONG_TIMEOUT
    if method == "transaction_entry":
        return [{"tx_hash": txh, "ledger_index": PROBE_TX_LEDGER}], 2, DEFAULT_TIMEOUT
    if method == "tx":
        return [{"transaction": txh}], 2, DEFAULT_TIMEOUT
    if method == "tx_history":
        return [{}], 1, DEFAULT_TIMEOUT
    if method == "validator_votes":
        return [{"validation_public_key": ctx.get("pubkey_node", "")}], 2, DEFAULT_TIMEOUT
    # Everything else (ADMIN gates, simple USER reads): empty params.
    return [{}], 2, DEFAULT_TIMEOUT


def store_response(payload):
    """Store a response redacted and size-capped. Returns (stored, meta)."""
    raw = json.dumps(payload, sort_keys=True).encode()
    size = len(raw)
    redacted, n_red = redact(payload)
    if size <= STORE_CAP_BYTES:
        return redacted, {"stored": "full", "size_bytes": size,
                          "redactions": n_red}
    head = json.dumps(redacted, sort_keys=True)[:STORE_CAP_BYTES]
    keys = list(redacted.keys()) if isinstance(redacted, dict) else []
    return {"_truncated": True, "size_bytes": size,
            "sha256": hashlib.sha256(raw).hexdigest(),
            "top_level_keys": keys,
            "head": head}, {"stored": "truncated", "size_bytes": size,
                            "redactions": n_red}


def fetch_live():
    """Probe every method once (server_info first). Returns (sample, log)."""
    fetch_log = []
    probes = {}
    ctx = {}
    started = utcnow_iso()

    # server_info first: it anchors the validated ledger and the node's
    # public key used by dependent probes.
    order = ["server_info"] + [m for m, *_ in METHOD_TABLE if m != "server_info"]
    for method in order:
        params, api_version, timeout = probe_params(method, ctx)
        body_params = list(params)
        if api_version != 2:
            body_params[0] = dict(body_params[0])
            body_params[0]["api_version"] = api_version
        payload, http_status, err, attempts, dt_ms = rpc_call(
            method, body_params, timeout)
        entry = {"method": method, "ok": err is None, "attempts": attempts,
                 "duration_ms": dt_ms, "error": err,
                 "http_status": http_status}
        if err is not None:
            probes[method] = {"method": method, "outcome": "transport_error",
                              "error": err, "attempts": attempts,
                              "params": body_params, "api_version": api_version}
            fetch_log.append(entry)
            continue
        stored, meta = store_response(payload)
        # Classify outcome from the envelope.
        if isinstance(payload, dict) and "_http_error" in payload:
            he = payload["_http_error"]
            code = "http_%d_forbidden" % he["status"] if he["status"] == 403 \
                else "http_%d" % he["status"]
            probes[method] = {
                "method": method, "outcome": "http_forbidden"
                if he["status"] == 403 else "http_error",
                "error_code": code, "error_code_num": he["status"],
                "error_message": he["body"],
                "attempts": attempts, "duration_ms": dt_ms,
                "params": body_params, "api_version": api_version,
                "result_keys": [], "response": stored, "response_meta": meta,
            }
            entry.update({"outcome": probes[method]["outcome"],
                          "error_code": code,
                          "response_bytes": meta["size_bytes"]})
            fetch_log.append(entry)
            continue
        if isinstance(payload, dict) and "error" in payload:
            e = payload["error"]
            if isinstance(e, dict):
                code = e.get("error_code", e.get("error", "unknown"))
                msg = e.get("error_message", "")
            else:
                code, msg = str(e), ""
            outcome = "rpc_error"
            code_num = ""
        elif isinstance(payload, dict) and "result" in payload:
            # rippled returns errors INSIDE result with status "error"
            # (e.g. {"result": {"error": "notSupported", "error_code": 75,
            # "status": "error"}}). A bare "result" is not a success.
            res = payload["result"]
            if isinstance(res, dict) and res.get("status") == "error":
                code = res.get("error", "unknown")
                code_num = res.get("error_code", "")
                msg = res.get("error_message", "")
                outcome = "rpc_error"
            else:
                code, code_num, msg, outcome = "", "", "", "success"
        else:
            code, code_num, msg, outcome = "malformed_envelope", "", "", "rpc_error"
        result = payload.get("result") if isinstance(payload, dict) else None
        result_keys = sorted(result.keys()) if isinstance(result, dict) else []
        probes[method] = {
            "method": method, "outcome": outcome, "error_code": code,
            "error_code_num": code_num,
            "error_message": msg, "attempts": attempts,
            "duration_ms": dt_ms, "params": body_params,
            "api_version": api_version, "result_keys": result_keys,
            "response": stored, "response_meta": meta,
        }
        entry.update({"outcome": outcome, "error_code": code,
                      "response_bytes": meta["size_bytes"]})
        fetch_log.append(entry)
        # Feed dependent probes.
        if method == "server_info" and outcome == "success" and isinstance(result, dict):
            info = result.get("info", {})
            if info.get("pubkey_node"):
                ctx["pubkey_node"] = info["pubkey_node"]
        if method == "account_nfts" and outcome == "success" and isinstance(result, dict):
            nfts = result.get("account_nfts") or []
            if nfts and isinstance(nfts[0], dict) and nfts[0].get("NFTokenID"):
                ctx["tokenid"] = nfts[0]["NFTokenID"]
    sample = {
        "harness_version": HARNESS_VERSION,
        "endpoint": RPC_ENDPOINT,
        "fetch_started_utc": started,
        "fetch_finished_utc": utcnow_iso(),
        "pinned_commit": PINNED_COMMIT,
        "probe_account": PROBE_ACCOUNT,
        "probe_tx_hash": PROBE_TX_HASH,
        "probes": probes,
    }
    return sample, fetch_log


def parse_handler_table(tree):
    """Re-parse Handler.cpp from the tree. Returns list of (name, role, cond)."""
    path = os.path.join(tree, "src/xrpld/rpc/detail/Handler.cpp")
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    pat = re.compile(
        r'\{"([a-z_0-9]+)",\s*byRef\(&(\w+)\),\s*Role::(\w+),\s*(\w+)', re.S)
    return [(m.group(1), m.group(3), m.group(4)) for m in pat.finditer(text)]


def tree_head(tree):
    try:
        out = subprocess.run(["git", "-C", tree, "rev-parse", "HEAD"],
                             capture_output=True, text=True, timeout=30)
        head = out.stdout.strip()
    except Exception:  # noqa: BLE001
        head = ""
    return {"tree_head_commit": head,
            "tree_head_matches_pinned": head == PINNED_COMMIT}


def analyse(sample, tree):
    """Derive summary.json, probe_results.csv, method_counts.csv,
    api_inventory.csv from the vendored sample."""
    probes = sample["probes"]
    by_method = {m: r for m, r, *_ in
                 [(row[0], row[1], row[2]) for row in METHOD_TABLE]}
    rows = []
    for method, role, cond, hfile, hline, apir in METHOD_TABLE:
        p = probes.get(method, {})
        exp_class, exp_note = EXPOSURE[method]
        rows.append({
            "method": method, "role": role, "condition": cond,
            "handler_file": hfile, "handler_line": hline,
            "api_range": apir, "exposure_class": exp_class,
            "exposure_note": exp_note,
            "outcome": p.get("outcome", "not_probed"),
            "error_code": p.get("error_code", ""),
            "error_code_num": p.get("error_code_num", ""),
            "error_message": p.get("error_message", ""),
            "attempts": p.get("attempts", ""),
            "duration_ms": p.get("duration_ms", ""),
            "api_version_probed": p.get("api_version", ""),
            "result_keys": ";".join(p.get("result_keys", [])),
            "response_bytes": (p.get("response_meta", {}) or {}).get("size_bytes", ""),
            "response_stored": (p.get("response_meta", {}) or {}).get("stored", ""),
        })

    outcomes = {}
    err_codes = {}
    for r in rows:
        outcomes[r["outcome"]] = outcomes.get(r["outcome"], 0) + 1
        if r["outcome"] == "rpc_error":
            err_codes[r["error_code"]] = err_codes.get(r["error_code"], 0) + 1

    admin_rows = [r for r in rows if r["role"] == "ADMIN"]
    admin_refused = [r for r in admin_rows
                     if r["error_code"] in ("noPermission", "forbidden",
                                            "no_permission",
                                            "http_403_forbidden")]
    admin_other = [r for r in admin_rows if r not in admin_refused]

    exp_counts = {}
    for r in rows:
        for cls in r["exposure_class"].split("|"):
            exp_counts[cls] = exp_counts.get(cls, 0) + 1

    # Key-exposure findings from the live probe.
    pubkey_out_live = [r["method"] for r in rows
                       if "PUBKEY_OUT" in r["exposure_class"]
                       and r["outcome"] == "success"]
    # Measured, not just classified: which live responses actually
    # contained a public-key or signature field (scanning the stored,
    # redacted responses). server_definitions is stored truncated, so
    # its scan is over the stored head only.
    KEY_FIELDS = ("SigningPubKey", "TxnSignature", "pubkey_node",
                  "public_key", "pubkey_validator", "pubkey_publisher",
                  "ephemeral_key", "master_key", "validation_key",
                  "signature")

    def _has_key_field(o):
        if isinstance(o, dict):
            return any(k in KEY_FIELDS for k in o) or \
                any(_has_key_field(v) for v in o.values())
        if isinstance(o, list):
            return any(_has_key_field(x) for x in o)
        return False

    key_fields_observed = sorted(
        m for m, p in probes.items()
        if p.get("outcome") == "success"
        and _has_key_field(p.get("response", {})))
    secret_in_methods = [m for m, (c, _) in EXPOSURE.items() if "SECRET_IN" in c]
    secret_out_methods = [m for m, (c, _) in EXPOSURE.items() if "SECRET_OUT" in c]
    sig_out_methods = [m for m, (c, _) in EXPOSURE.items() if "SIG_OUT" in c]

    # server_info snapshot from the vendored probe.
    si = probes.get("server_info", {})
    si_result = {}
    si_resp = si.get("response", {})
    if isinstance(si_resp, dict):
        si_result = si_resp.get("result", {}).get("info", {})
    server_snapshot = {
        "build_version": si_result.get("build_version", ""),
        "network_id": si_result.get("network_id", ""),
        "validated_ledger_seq": (si_result.get("validated_ledger") or {}).get("seq", ""),
        "complete_ledgers": si_result.get("complete_ledgers", ""),
        "ports": si_result.get("ports", []),
        "pubkey_node": si_result.get("pubkey_node", ""),
        "peers": si_result.get("peers", ""),
        "validation_quorum": si_result.get("validation_quorum", ""),
        "server_state": si_result.get("server_state", ""),
    }

    # Cross-check the embedded table against a fresh parse of the tree.
    table_check = {"checked": False, "matches": None, "mismatches": []}
    if tree and os.path.isfile(os.path.join(
            tree, "src/xrpld/rpc/detail/Handler.cpp")):
        parsed = parse_handler_table(tree)
        embedded = [(m, r, c) for m, r, c, _, _, _ in METHOD_TABLE
                    if m not in ("ledger", "version")]
        table_check["checked"] = True
        table_check["matches"] = sorted(parsed) == sorted(embedded)
        if not table_check["matches"]:
            ps, es = {x[0]: x for x in parsed}, {x[0]: x for x in embedded}
            for name in sorted(set(ps) | set(es)):
                if ps.get(name) != es.get(name):
                    table_check["mismatches"].append(
                        {"method": name, "tree": ps.get(name),
                         "embedded": es.get(name)})

    summary = {
        "harness_version": HARNESS_VERSION,
        "endpoint": RPC_ENDPOINT,
        "fetch_date_utc": sample.get("fetch_started_utc", ""),
        "pinned_commit": PINNED_COMMIT,
        "tree_check": tree_head(tree) if tree else {
            "tree_head_commit": "", "tree_head_matches_pinned": False},
        "handler_table_check": table_check,
        "methods_total": len(METHOD_TABLE),
        "methods_user": sum(1 for r in rows if r["role"] == "USER"),
        "methods_admin": sum(1 for r in rows if r["role"] == "ADMIN"),
        "grpc_methods_total": len(GRPC_METHODS),
        "ws_streams_total": len(WS_STREAMS),
        "probed_total": sum(1 for r in rows if r["outcome"] != "not_probed"),
        "outcomes": outcomes,
        "error_codes": err_codes,
        "admin_gate": {
            "admin_total": len(admin_rows),
            "refused_no_permission": len(admin_refused),
            "refused_methods": sorted(r["method"] for r in admin_refused),
            "other_outcomes": sorted(
                {"%s:%s" % (r["method"], r["outcome"]) for r in admin_other}),
        },
        "exposure_counts": exp_counts,
        "secret_accepting_methods": sorted(secret_in_methods),
        "secret_returning_methods": sorted(secret_out_methods),
        "signature_producing_methods": sorted(sig_out_methods),
        "pubkey_exposing_methods_live_success": sorted(pubkey_out_live),
        "pubkey_fields_observed_live": key_fields_observed,
        "server_snapshot": server_snapshot,
        # Transport observation, recorded at authoring time (2026-11-14)
        # with curl through the runtime egress proxy: the TLS session
        # terminates at the proxy (certificate re-signed by the sandbox
        # egress CA), so the origin server's own TLS version, cipher and
        # certificate are NOT observable from this machine. Recorded here
        # as a static observation, not a harness measurement.
        "transport_observation": {
            "observed": "2026-11-14T20:36:00Z",
            "via": "curl through the runtime egress proxy (CONNECT tunnel)",
            "tls_version": "TLSv1.3",
            "cipher": "TLS_AES_256_GCM_SHA384",
            "key_exchange": "X25519",
            "alpn": "http/1.1",
            "certificate": "re-signed by the sandbox egress CA; origin certificate not observable",
            "origin_tls": "not observable from this machine",
        },
        "sample_sha256": "",
    }
    return summary, rows


def write_json(path, obj):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=2, sort_keys=True)
        fh.write("\n")


def write_summary_txt(summary, path):
    lines = [
        "Post-quantum RPC and API surface security assessment",
        "Endpoint: %s" % summary["endpoint"],
        "Fetch date (UTC): %s" % summary["fetch_date_utc"],
        "Pinned tree: postfiatd main %s" % summary["pinned_commit"],
        "Tree HEAD matches pinned: %s"
        % summary["tree_check"]["tree_head_matches_pinned"],
        "Handler table matches embedded inventory: %s"
        % summary["handler_table_check"]["matches"],
        "",
        "Methods inventoried: %d JSON-RPC (%d USER, %d ADMIN) + %d gRPC + %d WS streams"
        % (summary["methods_total"], summary["methods_user"],
           summary["methods_admin"], summary["grpc_methods_total"],
           summary["ws_streams_total"]),
        "Methods probed live: %d" % summary["probed_total"],
        "Outcomes: %s" % json.dumps(summary["outcomes"], sort_keys=True),
        "Error codes: %s" % json.dumps(summary["error_codes"], sort_keys=True),
        "",
        "ADMIN gate: %d of %d ADMIN methods refused with HTTP 403 Forbidden"
        % (summary["admin_gate"]["refused_no_permission"],
           summary["admin_gate"]["admin_total"]),
        "Secret-accepting methods (USER-reachable): %s"
        % ", ".join(summary["secret_accepting_methods"]),
        "Secret-returning methods (all ADMIN): %s"
        % ", ".join(summary["secret_returning_methods"]),
        "Signature-producing methods: %s"
        % ", ".join(summary["signature_producing_methods"]),
        "Public-key-exposing methods returning success live: %s"
        % ", ".join(summary["pubkey_exposing_methods_live_success"]),
        "Methods whose live response actually contained a public-key or "
        "signature field: %s"
        % ", ".join(summary["pubkey_fields_observed_live"]),
        "",
        "Server snapshot: build %s, network_id %s, validated ledger %s, "
        "complete_ledgers %s, peers %s, validation_quorum %s"
        % (summary["server_snapshot"]["build_version"],
           summary["server_snapshot"]["network_id"],
           summary["server_snapshot"]["validated_ledger_seq"],
           summary["server_snapshot"]["complete_ledgers"],
           summary["server_snapshot"]["peers"],
           summary["server_snapshot"]["validation_quorum"]),
        "Node public key (server_info pubkey_node): %s"
        % summary["server_snapshot"]["pubkey_node"],
    ]
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="PFTL RPC/API quantum-exposure probe harness")
    ap.add_argument("--live", action="store_true",
                    help="probe the public RPC endpoint (default: offline, reuse vendored sample)")
    ap.add_argument("--out-dir", default=None,
                    help="results directory (default: <pack>/results)")
    ap.add_argument("--tree", default="/home/hatch/workspace/postfiatd-amendment/worktree-0085a1ff",
                    help="postfiatd tree to record HEAD for (default: pinned worktree)")
    args = ap.parse_args(argv)

    pack_dir = os.path.dirname(os.path.abspath(__file__))
    out_dir = args.out_dir or os.path.join(pack_dir, "results")
    os.makedirs(out_dir, exist_ok=True)

    if args.live:
        sample, fetch_log = fetch_live()
        write_json(os.path.join(out_dir, "probe_raw.json"), sample)
        write_json(os.path.join(out_dir, "fetch_log.json"), fetch_log)
    else:
        sample_path = os.path.join(out_dir, "probe_raw.json")
        with open(sample_path, encoding="utf-8") as fh:
            sample = json.load(fh)
        # Offline mode never overwrites the vendored live fetch log: it is
        # the record of the actual network probe. Only create a placeholder
        # if no fetch log was shipped at all.
        if not os.path.exists(os.path.join(out_dir, "fetch_log.json")):
            write_json(os.path.join(out_dir, "fetch_log.json"),
                       [{"request": "offline-mode",
                         "ok": True,
                         "error": None,
                         "note": "no network access; reused vendored results/probe_raw.json"}])

    summary, rows = analyse(sample, args.tree)
    # Deterministic content hash of the vendored sample, for traceability.
    with open(os.path.join(out_dir, "probe_raw.json"), "rb") as fh:
        summary["sample_sha256"] = hashlib.sha256(fh.read()).hexdigest()

    write_json(os.path.join(out_dir, "summary.json"), summary)
    write_summary_txt(summary, os.path.join(out_dir, "summary.txt"))

    with open(os.path.join(out_dir, "probe_results.csv"), "w",
              encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=[
            "method", "role", "condition", "handler_file", "handler_line",
            "api_range", "exposure_class", "exposure_note", "outcome",
            "error_code", "error_code_num", "error_message", "attempts", "duration_ms",
            "api_version_probed", "result_keys", "response_bytes",
            "response_stored"])
        w.writeheader()
        for r in rows:
            w.writerow(r)

    with open(os.path.join(out_dir, "method_counts.csv"), "w",
              encoding="utf-8", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["dimension", "key", "count"])
        for k in sorted(summary["outcomes"]):
            w.writerow(["outcome", k, summary["outcomes"][k]])
        for k in sorted(summary["error_codes"]):
            w.writerow(["error_code", k, summary["error_codes"][k]])
        for k in sorted(summary["exposure_counts"]):
            w.writerow(["exposure_class", k, summary["exposure_counts"][k]])
        w.writerow(["role", "USER", summary["methods_user"]])
        w.writerow(["role", "ADMIN", summary["methods_admin"]])
        w.writerow(["surface", "json_rpc_methods", summary["methods_total"]])
        w.writerow(["surface", "grpc_methods", summary["grpc_methods_total"]])
        w.writerow(["surface", "ws_streams", summary["ws_streams_total"]])

    with open(os.path.join(pack_dir, "api_inventory.csv"), "w",
              encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=[
            "method", "role", "condition", "handler_file", "handler_line",
            "api_range", "exposure_class", "exposure_note",
            "probe_outcome", "probe_error_code"])
        w.writeheader()
        for r in rows:
            w.writerow({
                "method": r["method"], "role": r["role"],
                "condition": r["condition"],
                "handler_file": r["handler_file"],
                "handler_line": r["handler_line"],
                "api_range": r["api_range"],
                "exposure_class": r["exposure_class"],
                "exposure_note": r["exposure_note"],
                "probe_outcome": r["outcome"],
                "probe_error_code": r["error_code"],
            })

    print("harness.py: OK (%s mode, %d methods probed, %d success, "
          "%d rpc_error, %d http_forbidden, %d transport_error)"
          % ("live" if args.live else "offline", summary["probed_total"],
             summary["outcomes"].get("success", 0),
             summary["outcomes"].get("rpc_error", 0),
             summary["outcomes"].get("http_forbidden", 0),
             summary["outcomes"].get("transport_error", 0)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
