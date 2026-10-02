# Simple CA

This tool is a simple CA intended to be executed via cli and http.

Mainly intended for development/testing environments.

## Build executable

```bash
go build
```

The same checks CI runs can be run locally:

```bash
gofmt -l .
go vet ./...
go install honnef.co/go/tools/cmd/staticcheck@v0.8.1
"$(go env GOPATH)/bin/staticcheck" ./...
go test -race ./...
```

## Download prebuilt binaries

Binaries are built by CI and attached to GitHub releases. Every push and pull
request runs the checks above plus a build of all supported targets, and a
release is published only after they pass.

- **Latest commit** on `main` (rolling release, tag `latest`):

```bash
curl -sSLf -o simple-ca \
    https://github.com/tomaluca95/simple-ca/releases/download/latest/simple-ca-linux-amd64
chmod +x simple-ca
```

The URL addresses the release by its tag (`releases/download/latest`).
GitHub's `releases/latest` form instead means "newest non-prerelease release",
which becomes a versioned release once one exists, so it would stop serving the
latest commit on `main`.

- **Specific version** from a tag (e.g. `1.3.5`):

```bash
curl -sSLf -o simple-ca \
    https://github.com/tomaluca95/simple-ca/releases/download/1.3.5/simple-ca-linux-amd64
chmod +x simple-ca
```

Platforms: `linux/amd64`, `linux/arm64`, `darwin/amd64`, `darwin/arm64`, `windows/amd64` (`.exe` suffix).
Checksums are in `simple-ca-checksums.txt` on each release. Each release also
attaches `LICENSE.txt`, `THIRD_PARTY_NOTICES.txt`, and
`simple-ca-source.tar.gz` (Corresponding Source under GPLv3).

## Update `config.yml`

```yaml
# debug, info, warn, error (default info)
log_level: debug
data_directory: ./tmp/
http_server:
    # A literal IPv4 or IPv6 address. The wildcards 0.0.0.0 and :: are
    # accepted, but only when written out; an omitted address is refused
    # rather than silently binding every interface.
    listen_address: 127.0.0.1
    # A real port; 0 (an arbitrary port the operator never sees) is refused.
    listen_port: 5000
    # Request and shutdown timeout, default 5s
    timeout: 5s
all_ca_configs:
    ca_1:
        subject:
            common_name: My CA 1
            country:
                - IT
            organization:
                - ACME Corp
            organizational_unit:
                - PKI
            locality: []
            province: []
            street_address: []
            postal_code: []
        validity:
            # When this CA's own certificate stops being valid, as an absolute
            # ISO 8601 timestamp with a time zone. See "CA lifetime" below.
            not_after: 2027-10-01T00:00:00Z
        key_config:
            # The key of this CA. See "Certificate keys" below for the
            # minimums this config is held to.
            type: rsa
            config:
                size: 4096
        # How long the CRL this CA publishes stays valid. The HTTP server
        # rewrites it every crl_ttl/4, see "CRL lifetime" below.
        crl_ttl: 12h
        # Backdate notBefore (and CRL thisUpdate) by this window so verifiers
        # whose clock lags the CA do not reject freshly issued certificates.
        # Default: 0s (no backdating). Maximum: 1h. This applies to the
        # certificates the CA issues from now on: the root's own notBefore was
        # fixed when it was signed, so changing this does not affect a load.
        clock_skew: 5m
        permitted_dns_domains_critical: true
        # Leading-dot form constrains names under example.com. An empty list
        # with the critical flag set does NOT constrain DNS names.
        permitted_dns_domains:
            - .example.com
        excluded_dns_domains: []
        permitted_ip_ranges:
            - 192.168.0.0/16
            - 10.0.0.0/8
        excluded_ip_ranges: []
        permitted_email_addresses: []
        excluded_email_addresses: []
        permitted_uri_domains: []
        excluded_uri_domains: []

        opa_url_sign: http://localhost:8181/v1/data/simple_ca_sign/allow
        opa_url_revoke: http://localhost:8181/v1/data/simple_ca_revoke/allow
        opa_url_issue_ca: http://localhost:8181/v1/data/simple_ca_issue_ca/allow
        # Per-call budget for each OPA endpoint, see "Timeouts" below.
        # Default: 500ms each.
        opa_timeout_sign: 500ms
        opa_timeout_revoke: 500ms
        opa_timeout_issue_ca: 500ms
```

## Bootstrap CAs

```bash
./simple-ca
```

The CLI flow also queries OPA (see [Authorization with OPA](#authorization-with-opa)): `opa_url_sign`/`opa_url_issue_ca` must be configured and reachable, or the run fails (`runtime: "cli"`, empty `authorization`).

### Certificate keys

One rule is applied to both ends of a chain: a key the CA signs with and a key a
client asks to have certified are held to the same minimum, because a CA whose
own key is weak undermines every certificate it issues, and every CRL it
publishes.

| algorithm | accepted |
|---|---|
| RSA | 2048 bits or more |
| ECDSA | P-256, P-384, P-521 |
| Ed25519 | always |
| anything else | refused |

The CA key comes from `key_config`, and the config is validated before anything
is generated, so a config naming a key below that table is refused with the
accepted values in the error. The key is measured again on every load, against
the size or curve the config asks for.

> **A CA whose key is on `P-224` does not start.** `P-224` is 112-bit security,
> below every current baseline, and neither Go nor `x509` objects to it, so the
> tool refuses it itself. There is no in-place re-key: changing the size or the
> curve of a key a CA already uses is refused, because it would not be the key
> its certificate was issued for. To move, bootstrap a new CA under a new
> `ca_id` with a key on an approved curve, have clients trust the new root, and
> retire the old one.

The key in a CSR is measured before the policy is even asked, so a policy that
forgets to check cannot talk the CA into issuing a certificate for a weak key.
A refusal is a `400 invalid CSR`, with the reason in the log.

This is a floor, not a policy. A deployment that wants a higher bar than "not
this weak" expresses it in OPA, which receives the key as
`proposed_certificate.public_key.algorithm` and `.bits`; the example policies
do exactly that and deny any algorithm they have no minimum for.

### Revoking

A certificate is revoked on the strength of the certificate itself. Two
endpoints do it, and both check the same things:

```bash
# by serial: the certificate stored under that serial
curl -sSLf -X POST http://localhost:5000/ca/$CA_ID/crt/revoke/12345

# by certificate: the certificate itself, PEM in a JSON body
jq -Rs '{certificate: .}' ${CERTS_DIR}/www.example.com.crt.pem \
  | curl -sSLf -H "Content-Type: application/json" -d @- \
    -X POST http://localhost:5000/ca/$CA_ID/crt/revoke
```

| request | refused with |
|---|---|
| payload that is not the documented JSON, or a certificate that does not parse | `400` |
| a serial no certificate is stored under | `404` |
| the CA certificate itself, on either endpoint | `409` |
| a certificate this CA did not issue, on either endpoint | `409` |
| a serial whose file holds a certificate with a different serial | `409` |
| a policy that does not allow it | `403` |

The serial endpoint names the file to read, so the serial is checked against
the certificate in it: a copy of a certificate under a second name is refused
rather than revoking the copy's name. That matters because the policy is asked
about a serial -- without the check a policy reasoning over `input.serial` could
be asked about one certificate and have the CRL name another.

The CA certificate itself is refused on both endpoints. `x509.Verify` accepts
the self-signed root as a leaf, because the root is in the trust store it is
verified against, so this is its own check rather than a side effect of
verification; without it a CA could publish a CRL revoking itself while still
serving the certificate at `/issuer.pem`.

The CRL index (`crl.yml` in the data directory) is where entries accumulate, and
it is checked on the way into the CRL rather than on the way in, so an entry
added by hand cannot be the CA certificate's serial either. **A data directory
whose `crl.yml` already carries the CA's serial will not start**: the CA refuses
to load rather than publish a CRL revoking itself, and the offending entry is
named in the error. Remove it, or hand it to the CA you actually want revoked.
Entries for serials this CA never issued are left alone -- they match no
certificate, so they cannot mislead anyone into distrusting one.

Every entry also carries `revocation_expires_at`, when the revocation stops
mattering: the `notAfter` of the certificate it names, which issuance already
caps at the CA's `notAfter`. Once that instant passes, the entry leaves the
index and the published CRL alike, so the list holds the still-relevant
revocations rather than growing with every certificate the CA has ever revoked.
An entry added by hand has to carry the field too; one that does not is refused
by name rather than kept forever or guessed at, because only the operator knows
when it should end.

`crl.yml` is read as exactly the one sequence the tool writes. An entry appended
under the empty index, or a second YAML document, is refused by name: a plain
YAML read sees only the first document and silently drops whatever follows, and
a revocation that quietly disappeared -- with the index rewritten without it -- is
the one failure a CRL must not have.

### CRL lifetime

`crl_ttl` (minimum `10m`) is how long the CRL this CA publishes stays valid: it
is the window between the `thisUpdate` and the `nextUpdate` of every CRL it
writes. While the HTTP server runs it rewrites the CRL every `crl_ttl/4`, so
the CRL a client fetches from `/ca/<ca_id>/crt/crl.pem` never reaches its
`nextUpdate` and a verifier that honours it keeps accepting the certificates
this CA signed. A refresh that fails is logged and retried on the next tick,
which leaves three attempts before the CRL expires. A CLI run writes the CRL
once, when it loads the CA and when it revokes a certificate, and then exits.

The endpoint answers `204 No Content` when the CRL file is missing -- removed by
hand, or simply absent from a restored data directory. A `200` with an empty
body would read to a client as "nothing is revoked", which is the wrong answer
in the one direction that matters.

Shorter `crl_ttl` means the CRL is rewritten more often, and every rewrite is
one commit in the git repository of the data directory. Ten minutes is the floor
for that reason: a rewrite signs a fresh revocation list, writes it and commits
it, so a `crl_ttl` of a few milliseconds buys no fresher list -- it buys a CA
that signs and commits as fast as the CPU allows while nobody is asking for
anything, measured at 67% of one core for `crl_ttl: 4ms` on an otherwise idle
CA. At ten minutes the rewrite is every 2m30s, finer than any client that polls
a CRL, and a `crl_ttl` below the floor is refused in the config report.

### CA lifetime

`validity.not_after` is when the CA's own certificate stops being valid, written
as an absolute ISO 8601 timestamp with a time zone: `2027-10-01T00:00:00Z`. It
is the only statement the configuration makes about the CA's lifetime, and the
load check compares it against the expiry in the certificate.

It is absolute rather than a distance from the moment the tool runs because a
distance is recomputed on every load, and "one month from now" is a different
length in different months. With a declared instant there is nothing to
recompute, so the same data directory and the same configuration load on any
date.

A configuration that outlives its `not_after` is refused when the CA is created
-- the tool will not sign a certificate that is born expired -- but a CA whose
expiry has passed still loads and still publishes its CRL, because what is left
of its issuance has to stay revocable and a tool that refuses to start cannot
revoke anything.

If the configuration names an instant other than the one the certificate
carries, the load refuses and names both, so the date to paste back is in the
error.

### Clock skew

`clock_skew` (default `0s`, maximum `1h`) backdates the `notBefore` of every
certificate this CA signs and the CRL `thisUpdate`, so a verifier whose clock
lags the CA by a few seconds still accepts a freshly issued certificate.

It does not apply to the CA's own certificate, whose window was fixed when it
was signed, and it is not part of the load check: changing it affects what is
issued from then on and nothing else, so it no longer has to be kept stable for
an existing CA.

### Data directory and git

Each CA keeps a git repository at `<data_directory>/<ca_id>/data/` that is its
audit log: **one commit per operation**, made of the state that matters.

- Every commit records the CA certificate, the revocation index (`crl.yml`)
  and the certificate that operation issued, so `git log` is the record of
  what the CA did and `git show <commit>:crt/<serial>.crt.pem` returns any
  certificate exactly as it was issued.
- The commit tree does **not** re-list every certificate the CA has ever
  issued. A certificate stays reachable through the commit that added it, so
  the repository grows with the number of certificates issued, not with its
  square, and issuing stays flat as the directory fills.
- Certificates and CSRs on disk are the CA's working set: `.gitignore` keeps
  them out of `git status`, and the working directory is what the CA serves
  and reads.

## HTTP server

The HTTP listener speaks plain HTTP only: bearer tokens and issued PEMs travel
in cleartext. Keep `listen_address` on a loopback address for local use, or put
TLS termination (and preferably mTLS or a reverse proxy) in front before
binding a non-loopback address. The server will bind `0.0.0.0` / `::` if you
write those addresses out, but that is an intentional exposure, not a default.

### Timeouts

`http_server.timeout` (default `5s`) bounds a single request: how long the
server waits for the request headers, for the rest of the request, and for the
response to be written, plus how long a kept-alive connection may stay idle. A
client that opens a connection and then stalls is dropped after the timeout
instead of holding it forever.

Each OPA endpoint has its own per-call budget: `opa_timeout_sign`,
`opa_timeout_revoke` and `opa_timeout_issue_ca` (default `500ms` each) bound
how long the policy may take, both over HTTP and in the CLI/spool flow. Raise
one when its policy is slow -- a check that outruns its budget fails the request
instead of holding it. Because it applies first, `http_server.timeout` must be
at least as large as the slowest policy budget the requests must survive; a
requester that raises the request timeout but not the OPA budget changes
nothing for the policy call. OPA calls also ignore `HTTP_PROXY` /
`HTTPS_PROXY`: the caller `Authorization` value is sent in the OPA JSON body,
so an environment proxy must not be able to intercept it.

A request that exceeds `http_server.timeout` is cut off while the server keeps
working on it: the certificate may still be issued and written to disk, but the
client is no longer there to receive it.

### Graceful shutdown

`SIGINT` and `SIGTERM` stop the accept loop and wait for the requests still in
flight, so a sign request is never interrupted halfway through writing a
certificate; the server exits `0` once they are done. The wait is bounded by the
same `timeout`, which is exactly the budget a request that is still viable has
left. If a request cannot finish within it, the connections are closed forcibly
and the process exits `2`, logging the failure:

```
level=INFO msg="shutting down the http server" graceful_shutdown_timeout=5s
level=INFO msg="http request" method=POST path=/ca/ca_1/csr/sign status=200 duration=2.03s request_id=550e8400-e29b-41d4-a716-446655440000
level=INFO msg="http server stopped"
```

## Logging

Logs go to stderr as one `key=value` per field, in a single format for the whole
program. `log_level` in `config.yml` picks the minimum level (`debug`, `info`,
`warn`, `error`; `info` by default): `debug` shows every CSR and CA operation,
while `info` and above keep the CA lifecycle, request outcomes and problems.
Denied requests are logged at `warn`, authorization failures and other internal
errors at `error`.

In HTTP mode every record of one request carries the same `request_id`, so the
whole request can be traced together:

```
level=INFO msg="loaded CA" ca_id=ca_1 issuer="CN=My CA 1"
level=DEBUG msg="loading CSR" ca_id=ca_1 subject="CN=www.example.com" request_id=550e8400-e29b-41d4-a716-446655440000
level=DEBUG msg="prepared certificate, pending authorization" ca_id=ca_1 serial=... request_id=550e8400-e29b-41d4-a716-446655440000
level=WARN msg="authorization denied signing" ca_id=ca_1 err="not authorized" request_id=550e8400-e29b-41d4-a716-446655440000
level=INFO msg="http request" method=POST path=/ca/ca_1/csr/sign status=403 duration=12.3ms request_id=550e8400-e29b-41d4-a716-446655440000
```

`request_id` is taken from the `X-Request-ID` request header when it is
alphanumeric and at most 36 characters; a longer header is refused with a 400.
A missing or non-alphanumeric id is replaced by a generated UUID. Whichever id
a request used is returned in the `X-Request-ID` response header, so the client
can correlate its side of the request with the CA's logs. `ca_id` is bound to
the logger of each CA, so records from different CAs stay distinguishable in
the same stream.

## Local use

### Generate csr using openssl

```bash
openssl req \
    -nodes \
    -subj "/CN=www.example.com" \
     -addext "subjectAltName = DNS:www.example.com , DNS:www2.example.com" \
    -addext "extendedKeyUsage = serverAuth, clientAuth" \
    -addext "keyUsage=keyEncipherment" \
    -newkey rsa:2048 \
    -keyout ${KEYS_DIR}/www.example.com.key.pem \
    -out ${CSRPOOL}/www.example.com.csr.pem


openssl req \
    -in ${CSRPOOL}/www.example.com.csr.pem \
    -noout \
    -text
```

### Sign all CSRs and generate new CRL

```bash
./simple-ca
```

`./simple-ca` signs every CSR found in each CA's `data/csr/` spool and refreshes
the CRL. An entry that fails in a way a retry will not fix -- a request the
policy refuses, an invalid CSR or lifetime -- is moved to
`data/csr/signature-failed/` with the reason in the log line, so a single bad
entry does not block every later run. Entries that fail transiently stay in the
spool and are retried. Directories and non-PEM files in the spool are skipped
without blocking the run.

## Authorization with OPA

The tool uses Open Policy Agent (OPA) for authorization, both for the HTTP server and the CLI/spool flow (`./simple-ca`).

Each CA needs three policy URLs:

- `opa_url_sign`: leaf certificate signing.
- `opa_url_issue_ca`: subordinate-CA issuance. simple-ca routes a request here
  automatically when the resulting certificate is a CA (`is_ca == true`), so the
  two cases never share a policy.
- `opa_url_revoke`: revocation.

Each endpoint also has a per-call timeout, `opa_timeout_sign`,
`opa_timeout_revoke` and `opa_timeout_issue_ca` (default `500ms` each), that
bounds how long the policy may take; see [Timeouts](#timeouts) under HTTP
server.

### Example policies

Tested, restrictive example policies are available in
[`examples/opa-policies/`](examples/opa-policies/). They are **demos**: the
tokens are public placeholders (`CHANGE-ME-...`), and `runtime == "cli"` is
treated as a fully trusted local operator with no bearer token. Change the
tokens and drop or tighten the CLI trust rule before copying these files onto a
shared host.

- `simple_ca_sign.rego`: authorizes leaves; requires a token (HTTP) or a
  trusted local operator (CLI), requires at least one DNS SAN on the
  `*.example.com` allowlist (an empty SAN list is denied), keeps the subject CN
  inside that allowlist (or empty), bounds the validity, allowlists the
  extension OIDs a signed leaf may carry, and denies `certSign` / `crlSign`
  key usage -- an explicit `basicConstraints: CA:FALSE` from a CSR generator
  does not disqualify a leaf. The Go process also refuses leaf `keyCertSign` /
  `cRLSign` before the certificate is persisted.
- `simple_ca_issue_ca.rego`: authorizes subordinate-CA issuance; requires the
  officer token (HTTP) or a trusted local operator (CLI), allowlists the
  extension OIDs a subordinate CA may carry, and requires `max_path_len` to be
  present and equal to `0` (no further CA minting). A CA asking for an
  unlisted extension (an `authorityInfoAccess` pointing clients at a foreign
  `caIssuers`, for instance) is refused. The root this tool issues still has
  no path-length constraint of its own.
- `simple_ca_revoke.rego`: requires a token and allows any authenticated
  caller (leaf or officer token) to revoke a **non-CA** leaf. It forbids
  revoking the root (serial `1`) and does **not** authorize subordinate-CA
  revocation; add that in a deployment-specific policy if you need it.

CSR extensions are copied into the certificate template before the policy is
asked. The Go process enforces key strength, CA name constraints, and refuses
leaf certificates that carry `keyCertSign` or `cRLSign`; broader **extension
allowlisting remains the policy's job**. A permissive policy (`allow := true`)
still yields an extension-driven CA aside from that leaf KU floor.

Point the CA config at their decision paths:

```yaml
all_ca_configs:
    ca_1:
        # ...
        opa_url_sign: http://localhost:8181/v1/data/simple_ca_sign/allow
        opa_url_revoke: http://localhost:8181/v1/data/simple_ca_revoke/allow
        opa_url_issue_ca: http://localhost:8181/v1/data/simple_ca_issue_ca/allow
```

Serve those files with OPA:

```bash
docker container run \
    -p 8181:8181 \
    -v $(pwd)/examples/opa-policies:/policies \
    openpolicyagent/opa run --addr 0.0.0.0:8181 --server /policies
```

The examples expect `Authorization: Bearer CHANGE-ME-leaf-signer` to sign or
revoke a leaf and `Authorization: Bearer CHANGE-ME-sub-ca-officer` to issue a
subordinate CA. Both constants sit at the top of the policy files: change them
before using the examples for anything real, and copy the directory if you want
to keep your changes out of the repository.

### What the policy receives

The policy is asked **twice** for each sign: once on a provisional view of the
certificate (before the CA private key is used) and once on the signed
artifact that will be persisted. Both must allow. The policy inspects the
certificate, not the raw request:

```json
{
  "runtime": "http",
  "remote_addr": "127.0.0.1:51234",
  "authorization": "<Authorization header, empty for cli>",
  "proposed_certificate": {
    "subject": { "common_name": "www.example.com", "country": [], "organization": [], "organizational_unit": [], "locality": [], "province": [], "street_address": [], "postal_code": [] },
    "serial_number": "116148005341474726464640606874966390269",
    "not_before": "2026-09-26T18:30:58Z",
    "not_after": "2026-09-26T19:30:58Z",
    "is_ca": false,
    "basic_constraints_valid": false,
    "key_usage": [],
    "extended_key_usage": [],
    "dns_names": ["www.example.com"],
    "email_addresses": [], "ip_addresses": [], "uris": [],
    "public_key": { "algorithm": "RSA", "bits": 2048 },
    "signature_algorithm": "SHA256-RSA",
    "extensions": [
      { "oid": "2.5.29.17", "critical": false, "value_hex": "3023..." }
    ]
  }
}
```

`extensions` lists every extension with its OID, criticality and raw value, so a
policy can never be blind to one. `max_path_len` is absent when no path length
constraint applies (leaves and CAs without a pathlen); it is present (including
`0`) only when the certificate really carries one.

Revocation requests carry the same certificate under `input.certificate`, plus
`input.serial`: the serial of that certificate as a JSON number, so a policy
compares it with a number (`input.serial == 1`) and not with a string. A
certificate serial is up to 128 bits, which a client decoding the input as a
double cannot hold exactly, so `certificate.serial_number` stays a string for
anything that has to print a serial. `input.serial` is read off the certificate
and never off the request, so a policy is always deciding about the certificate
that ends up in the CRL.

`runtime` is `"http"` for the server and `"cli"` for the spool/CLI flow (empty
`authorization`, no `remote_addr`). The example policies treat CLI as trusted;
remove `runtime == "cli"` from the examples to forbid the offline flow.

## HTTP server

### Run

```bash
./simple-ca http
```

### Requests

```bash
openssl req \
    -nodes \
    -subj "/CN=www.example.com" \
    -addext "subjectAltName = DNS:www.example.com , DNS:www2.example.com" \
    -addext "extendedKeyUsage = serverAuth, clientAuth" \
    -addext "keyUsage=keyEncipherment" \
    -newkey rsa:2048 \
    -keyout ${KEYS_DIR}/www.example.com.key.pem \
    -out ${CSR_DIR}/www.example.com.csr.pem


openssl req \
    -in ${CSR_DIR}/www.example.com.csr.pem \
    -noout \
    -text

CA_ID=ca_1

# The example policies expect a bearer token; your own policies may ignore it.
# Use the officer token instead when the CSR requests a subordinate CA.
OPA_TOKEN="CHANGE-ME-leaf-signer"

# Optional: request a specific expiry (RFC 3339) via the not_after body field.
# The requested value is capped by the CA's own expiry and validated by the OPA
# sign policy (input.proposed_certificate.not_after); when the field is absent
# the certificate is valid for 1 hour. A value in the past is rejected with 400
# ("invalid not_after: not in the future").
# `date` takes a different relative-time spelling by system: GNU (Linux) uses
# `-d "+2 hours"` and BSD (macOS) uses `-v+2H`. The line below tries the BSD
# spelling first and falls back to the GNU one, so it works on both.
NOT_AFTER=$(date -u -v+2H '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || date -u -d '+2 hours' '+%Y-%m-%dT%H:%M:%SZ')

jq -Rs --arg na "${NOT_AFTER}" '{csr: ., not_after: $na}' \
    ${CSR_DIR}/www.example.com.csr.pem \
  | curl \
    -sSLf \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${OPA_TOKEN}" \
    -d @- \
    -X POST \
    http://localhost:5000/ca/$CA_ID/csr/sign

# Revoke by serial.
curl \
    -sSLf \
    -H "Authorization: Bearer ${OPA_TOKEN}" \
    -X POST \
    http://localhost:5000/ca/$CA_ID/crt/revoke/12345

# Or revoke the certificate itself, which needs no serial to be right about.
jq -Rs '{certificate: .}' ${CERTS_DIR}/www.example.com.crt.pem \
  | curl \
    -sSLf \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${OPA_TOKEN}" \
    -d @- \
    -X POST \
    http://localhost:5000/ca/$CA_ID/crt/revoke
```

## License

Copyright (C) 2024-2026 Toma Luca.

This program is free software under the GNU General Public License version 3
(`GPL-3.0-only`); see [LICENSE.txt](LICENSE.txt). Third-party notices for
linked Go modules are in [THIRD_PARTY_NOTICES.txt](THIRD_PARTY_NOTICES.txt).
