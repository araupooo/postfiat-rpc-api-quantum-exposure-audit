#!/usr/bin/env python3
"""Build docs/index.html (the canonical results page) from the derived
outputs. Deterministic: same inputs produce byte-identical output."""

import csv
import html
import json
import os

PACK_DIR = os.path.dirname(os.path.abspath(__file__))
RESULTS = os.path.join(PACK_DIR, "results")


def esc(s):
    return html.escape(str(s), quote=True)


def main():
    with open(os.path.join(RESULTS, "summary.json"), encoding="utf-8") as fh:
        s = json.load(fh)
    with open(os.path.join(RESULTS, "probe_results.csv"),
              encoding="utf-8", newline="") as fh:
        rows = list(csv.DictReader(fh))

    def section(title, body):
        return "<h2>%s</h2>\n%s\n" % (esc(title), body)

    snap = s["server_snapshot"]
    admin = s["admin_gate"]

    headline = (
        "<p>The PFTL testnet JSON-RPC surface exposes <strong>%d methods</strong> "
        "(%d USER, %d ADMIN) plus %d gRPC methods and %d WebSocket streams. "
        "All %d JSON-RPC methods were probed live from an unauthenticated "
        "client on %s: <strong>%d succeeded, %d returned an RPC error, "
        "%d were refused with HTTP 403 Forbidden, "
        "%d failed at transport</strong>. The ADMIN gate held for "
        "<strong>%d of %d</strong> ADMIN methods (refused with "
        "HTTP 403 Forbidden). <strong>%d methods accept secrets</strong> in the "
        "request body and <strong>%d produce signatures</strong> — all of "
        "them reachable without authentication.</p>"
        % (s["methods_total"], s["methods_user"], s["methods_admin"],
           s["grpc_methods_total"], s["ws_streams_total"],
           s["probed_total"], s["fetch_date_utc"],
           s["outcomes"].get("success", 0),
           s["outcomes"].get("rpc_error", 0),
           s["outcomes"].get("http_forbidden", 0),
           s["outcomes"].get("transport_error", 0),
           admin["refused_no_permission"], admin["admin_total"],
           len(s["secret_accepting_methods"]),
           len(s["signature_producing_methods"])))

    server_rows = "".join(
        "<tr><td>%s</td><td>%s</td></tr>" % (esc(k), esc(v))
        for k, v in [
            ("Endpoint", s["endpoint"]),
            ("Fetch date (UTC)", s["fetch_date_utc"]),
            ("Pinned tree", "postfiatd main " + s["pinned_commit"]),
            ("Tree HEAD matches pinned", str(s["tree_check"]["tree_head_matches_pinned"])),
            ("Handler table matches embedded inventory", str(s["handler_table_check"]["matches"])),
            ("Build version", snap["build_version"]),
            ("Network ID", snap["network_id"]),
            ("Validated ledger", snap["validated_ledger_seq"]),
            ("Complete ledgers", snap["complete_ledgers"]),
            ("Peers", snap["peers"]),
            ("Validation quorum", snap["validation_quorum"]),
            ("Listening ports (server_info)", ", ".join(
                "%s: %s" % (p.get("port"), "/".join(p.get("protocol", [])))
                for p in snap["ports"])),
            ("Node public key (pubkey_node)", snap["pubkey_node"]),
        ])

    exp_rows = "".join(
        "<tr><td>%s</td><td>%d</td></tr>" % (esc(k), v)
        for k, v in sorted(s["exposure_counts"].items()))

    out_rows = "".join(
        "<tr><td>%s</td><td>%d</td></tr>" % (esc(k), v)
        for k, v in sorted(s["outcomes"].items()))

    err_rows = "".join(
        "<tr><td>%s</td><td>%d</td></tr>" % (esc(k), v)
        for k, v in sorted(s["error_codes"].items()))

    def method_table(filter_fn):
        body = ""
        for r in rows:
            if not filter_fn(r):
                continue
            body += ("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td>"
                     "<td>%s</td><td>%s</td></tr>"
                     % (esc(r["method"]), esc(r["role"]),
                        esc(r["exposure_class"]), esc(r["outcome"]),
                        esc(r["error_code"]), esc(r["exposure_note"])))
        return ("<table><tr><th>Method</th><th>Role</th><th>Exposure</th>"
                "<th>Probe outcome</th><th>Error code</th>"
                "<th>Key-material note</th></tr>" + body + "</table>")

    secret_list = "".join("<li><code>%s</code></li>" % esc(m)
                          for m in s["secret_accepting_methods"])
    sig_list = "".join("<li><code>%s</code></li>" % esc(m)
                       for m in s["signature_producing_methods"])
    secret_out_list = "".join("<li><code>%s</code></li>" % esc(m)
                              for m in s["secret_returning_methods"])
    live_pubkey = "".join("<li><code>%s</code></li>" % esc(m)
                          for m in s["pubkey_exposing_methods_live_success"])
    observed_pubkey = "".join("<li><code>%s</code></li>" % esc(m)
                             for m in s["pubkey_fields_observed_live"])

    transport = s["transport_observation"]
    transport_html = (
        "<p>Observed %s via curl through the runtime egress proxy "
        "(CONNECT tunnel): TLS %s, cipher %s, key exchange %s, ALPN %s. "
        "The certificate presented was %s — the TLS session terminates "
        "at the proxy, so the origin server's own TLS version, cipher "
        "and certificate are <strong>not observable from this machine</strong> "
        "and no claim is made about them.</p>"
        % (esc(transport["observed"]), esc(transport["tls_version"]),
           esc(transport["cipher"]), esc(transport["key_exchange"]),
           esc(transport["alpn"]), esc(transport["certificate"])))

    page = """<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8">
<title>Post-Quantum RPC and API Surface Security Assessment</title>
<style>body{font-family:system-ui,sans-serif;max-width:960px;margin:2em auto;padding:0 1em;line-height:1.5}table{border-collapse:collapse;margin:1em 0}th,td{border:1px solid #ccc;padding:4px 8px;text-align:left;vertical-align:top}th{background:#f0f0f0}code{background:#f4f4f4;padding:0 3px}</style>
</head>
<body>
<h1>Post-Quantum RPC and API Surface Security Assessment</h1>
<p>Which PFTL API methods expose public keys, signatures, or signing
capability to an unauthenticated caller; which are gated to ADMIN; and
how the surface should migrate to post-quantum signatures.</p>
""" + headline + section("Server probed", "<table>" + server_rows + "</table>") + section(
    "Outcomes", "<table><tr><th>Outcome</th><th>Methods</th></tr>" + out_rows +
    "</table><table><tr><th>Error code</th><th>Methods</th></tr>" + err_rows + "</table>") + section(
    "Exposure classes", "<table><tr><th>Class</th><th>Methods</th></tr>" + exp_rows + "</table>") + section(
    "Secret-accepting methods (USER-reachable, no authentication)",
    "<ul>" + secret_list + "</ul><p>These take a secret, seed, passphrase "
    "or seed_hex in the request body. The secret travels to the server in "
    "the request and is visible to the endpoint operator and to any "
    "TLS-terminating proxy in front of it.</p>") + section(
    "Signature-producing methods",
    "<ul>" + sig_list + "</ul>") + section(
    "Secret-returning methods (all ADMIN-gated)",
    "<ul>" + secret_out_list + "</ul><p>Each was probed with empty "
    "parameters and refused with HTTP 403 Forbidden, so no secret "
    "material was returned. Had the ADMIN gate been misconfigured, "
    "these would return generated secrets to any caller.</p>") + section(
    "Public-key-exposing methods that returned success live",
    "<ul>" + live_pubkey + "</ul><p>Of these, the responses that "
    "actually contained a public-key or signature field in this probe "
    "were:</p><ul>" + observed_pubkey + "</ul><p><code>ledger</code>, "
    "<code>ledger_data</code> and <code>ledger_entry</code> returned no "
    "key-carrying record in the probed responses "
    "(<code>ledger</code> was probed with "
    "<code>transactions:false</code>; the <code>ledger_data</code> page "
    "and the <code>ledger_entry</code> record contained no payment "
    "channel). Their PUBKEY_OUT classification is code-derived: they "
    "return keys when the requested data includes them.</p>") + section(
    "Transport observation", transport_html) + section(
    "All methods (USER)", method_table(lambda r: r["role"] == "USER")) + section(
    "All methods (ADMIN)", method_table(lambda r: r["role"] == "ADMIN")) + """
<h2>Migration verdict</h2>
<p>The signing entry points (<code>sign</code>, <code>sign_for</code>,
<code>channel_authorize</code>, and the deprecated <code>submit</code>
signing path) must gain hybrid classical + ML-DSA signing before a
cryptographically relevant quantum computer exists, because every
signature they produce is recorded on the public ledger forever. The
read surface (<code>account_tx</code>, <code>tx</code>,
<code>ledger</code>, <code>transaction_entry</code>,
<code>tx_history</code>) needs no migration — it only relays what the
ledger already records — but its consumers must be ready to verify
ML-DSA signatures. The ADMIN gate is the only thing standing between
an unauthenticated caller and <code>wallet_propose</code> /
<code>validation_create</code> secret generation: it is enforced in
code (<code>RPCHandler.cpp:166</code>) but depends on per-port
configuration (<code>admin</code> nets, <code>admin_user</code> /
<code>admin_password</code>), so it must be audited per deployment, not
assumed. Full design, phased plan, costs and rollback notes:
<code>migration_design.md</code>.</p>
<h2>Files</h2>
<ul>
<li><code>api_inventory.csv</code> / <code>api_inventory.md</code> — the full method inventory with file:line evidence</li>
<li><code>results/probe_raw.json</code> — vendored raw probe responses (redacted, size-capped)</li>
<li><code>results/fetch_log.json</code> — per-request probe outcomes</li>
<li><code>results/summary.json</code> / <code>results/summary.txt</code> — aggregate measured results</li>
<li><code>results/probe_results.csv</code> — one row per method</li>
<li><code>results/method_counts.csv</code> — counts by outcome, error code, exposure class and role</li>
<li><code>exposure_analysis.md</code> — per-method quantum-exposure analysis</li>
<li><code>migration_design.md</code> — hybrid ML-DSA migration design, phased plan, costs</li>
<li><code>claim_evidence_index.md</code> — every headline claim mapped to file, field and line</li>
<li><code>REPRODUCTION.md</code> — fresh-environment reproduction record</li>
<li><code>results/run_log.txt</code> — raw console log of the fresh-environment run</li>
</ul>
<h2>Scope and limits</h2>
<p>All probe counts describe one unauthenticated probe run against the
public endpoint on the fetch date above. The gRPC surface (4 methods)
and the WebSocket subscription streams were inventoried from code
only: the gRPC and WebSocket ports are not reachable from the audit
machine. The origin server's TLS configuration is not observable from
this machine (egress proxy re-signs the certificate). No secret,
seed or passphrase was ever sent to the endpoint. See
<code>assumptions.md</code> for the full list.</p>
</body>
</html>
"""
    with open(os.path.join(PACK_DIR, "docs", "index.html"), "w",
              encoding="utf-8") as fh:
        fh.write(page)
    print("build_derived.py: OK (docs/index.html)")


if __name__ == "__main__":
    main()
