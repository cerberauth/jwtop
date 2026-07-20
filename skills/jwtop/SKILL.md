---
name: jwtop
description: Drive the jwtop CLI (github.com/cerberauth/jwtop) for any JWT task — decoding, verifying signatures, creating/forging tokens, re-signing, and JWT security testing (weak-secret cracking, alg=none, HMAC key confusion, kid injection, psychic signatures, and live endpoint probing). Use this skill whenever the user pastes a JWT, asks what a token contains, asks to verify/forge/sign a token, wants to test an API's JWT handling for auth-bypass vulnerabilities, mentions jwt_tool-style attacks, or is doing authorized pentest/CTF work involving JSON Web Tokens. Trigger even if they don't say "jwtop" by name — e.g. "can you check if this token is exploitable", "forge me an admin JWT for testing", "does this API accept alg=none".
---

# jwtop

jwtop is a Go CLI (this repo) covering the full JWT lifecycle: `decode`,
`verify`, `create`, `sign`, plus a security-testing layer: `crack` (analyze/probe
for vulnerabilities) and `exploit` (apply one known technique, print the
resulting token).

**`crack` and `exploit` are for authorized testing only** — your own
systems, a pentest engagement with signed-off scope, or a CTF. Never point
`--url` at a target without permission. If the user's request doesn't make
authorization clear and the target looks like it could be third-party, ask
before running online probes.

## Use the installed `jwtop` command

Every example below is a plain `jwtop <command>` invocation — assume `jwtop`
is already on `PATH` and call it directly, the same way you'd call `git` or
`curl`. Don't build from source as your default; that only matters on the
rare occasion `jwtop -v` fails, and even then it's a quick fix, not a step to
perform up front on every task:

- Inside a checkout of the `cerberauth/jwtop` repo: `go build -o jwtop .` —
  fast, no network needed, always available.
- Anywhere else: `go install github.com/cerberauth/jwtop@latest` — needs
  network and a working Go toolchain; if that stalls (e.g. fetching a Go
  version bump), a local repo checkout's `go build` is more reliable than
  waiting on it.

## Pick the right command

| User wants to... | Command |
|---|---|
| See what's inside a token (no trust implied) | `decode` |
| Confirm a token's signature is valid | `verify` |
| Mint a brand-new token from scratch | `create` |
| Change an existing token's algorithm/key/claims-signature | `sign` |
| Know *whether* a token/endpoint is vulnerable, across many techniques | `crack` |
| Produce *one specific* forged token to hand to something else (a browser, a repro script, a report) | `exploit <technique>` |

`crack` and `exploit` overlap in technique but differ in purpose: `crack` is
a scanner — it runs the applicable checks, judges pass/fail against a
baseline, and emits a report. `exploit <technique>` is a single tool — it
always produces a token, with no judgment about whether it will work,
because it doesn't have a target to test it against.

## decode — inspect without trusting

```sh
jwtop decode <token>
```

Prints header, claims, and raw signature. No signature check happens — use
this for "what's in this token" questions, or as the first step before
choosing an exploit (the `alg` field determines which techniques apply: HMAC
weak-secret / blank-secret / kid-injection need `HS*`; hmacconfusion needs
`RS*`/`ES*`/`PS*`; psychicsig needs `ES*` specifically).

## verify — check a signature

```sh
jwtop verify <token> --secret mysecret          # HMAC
jwtop verify <token> --key public.pem           # RSA/ECDSA, file or URL
jwtop verify <token> --jwks https://host/.well-known/jwks.json
```

Exits non-zero on an invalid token — safe to use in a shell conditional.

## create — mint a new token

```sh
jwtop create --alg HS256 --secret mysecret \
  --sub user123 --iss myapp --aud myapi --exp 1h --iat \
  --claim role=admin --claim plan=pro
```

`--alg` plus one of `--secret` (HMAC) or `--key` (RSA/ECDSA private key,
file or URL) is required. `--claim key=value` is repeatable; values that
parse as an int or bool are stored typed, everything else as a string.
Reach for `create` when the user wants a clean synthetic token for a test
fixture — not when they're mutating a real captured token (that's `sign`).

## sign — re-sign an existing token

```sh
jwtop sign <token> --alg RS256 --key private.pem   # change algorithm/key
jwtop sign <token> --alg none                       # strip to alg=none
```

Preserves the original claims, changes only the signing. Useful for testing
how a server reacts to the same claims under a different algorithm, distinct
from the `exploit` subcommands which target specific known CVE-style bugs.

## crack — scan for vulnerabilities

```sh
# Offline: pure crypto checks, no network call
jwtop crack <token>
jwtop crack <token> --wordlist secrets.txt --secret guess1 --secret guess2

# Online: probe a live server per technique
jwtop crack <token> --url https://api.example.com/protected
jwtop crack <token> --url https://api.example.com/protected --key public.pem   # enables hmacconfusion
```

Offline checks run always: `alg=none` already set, blank HMAC secret, empty
signature, weak-secret dictionary attack. Adding `--url` additionally probes
live: 4-way `alg=none` casing, `hmacconfusion` (needs `--key`), `psychicsig`
(ECDSA tokens only), `kidinjection` (SQL + path traversal). A technique
counts as vulnerable when the server's response status differs from the
baseline (auto-detected by sending a deliberately invalid token, or set
explicitly with `--expected-status` if the server already rejects the
original token).

**Token placement** — if the target doesn't take the JWT as a bare
`Authorization: Bearer <token>` header, tell `crack` where it actually goes.
Check how the app sends the token today (a curl command, HAR file, or app
code) before guessing:

```sh
--token-in cookie --token-name session
--token-in query  --token-name access_token
--token-in body   --token-name jwt
--token-in header --token-name X-Auth-Token --token-prefix "Token "
```

**Report formats** — `--format json|jsonl|sarif|markdown|html|terminal`
(default `terminal`), `--output <file>` to write instead of stdout. Use
`json` or `markdown` when the user wants the result saved into a report or
piped elsewhere; use the default `terminal` for a quick human read. Exit
code is `0` if at least one vulnerability was found, `1` otherwise — useful
as a CI gate on token fixtures.

The `markdown`/`html`/`terminal`/`sarif` reports describe *that* a finding
like Weak Secret fired (severity, CWE, CVSS) but not the recovered value
itself — only `--format json`'s `findings[].extra.detail` carries the actual
cracked secret. If the user needs the concrete secret (not just the
vulnerability verdict) alongside a shareable report, run `crack --format
json` once to pull the value and fold it into whatever report format you
hand back — don't assume the markdown/html report already has it.

Full technique-by-technique detail (CWE, CVSS, what "vulnerable" means for
each): `references/techniques.md`.

## exploit — produce one forged token

```sh
jwtop exploit algnone <token> [--all]
jwtop exploit blanksecret <token>
jwtop exploit nullsig <token>
jwtop exploit hmacconfusion <token> --key public.pem
jwtop exploit psychicsig <token>
jwtop exploit weaksecret <token> [--wordlist file] [--secret guess]...
jwtop exploit kidinjection <token> --mode sql|path|raw [--sql-table t] [--path p] [--kid v] [--secret s]
```

Each subcommand prints the resulting token to stdout and nothing else —
pipe it straight into a curl command or a repro script. Pick the subcommand
by matching the token's `alg` (decode first if unsure) and the vulnerability
class you're demonstrating. `weaksecret` and `kidinjection` (sql/path
modes) print the *recovered secret*/forged token on success and exit
non-zero on failure — don't assume success without checking the exit code.

Detail on each technique's default payloads and the CVE/research behind it:
`references/techniques.md`.

## Typical request → workflow

**"What's in this token?"** → `decode`. Add `verify` only if they also gave
you a secret/key/JWKS and want the signature checked.

**"Forge me a token with `role=admin`"** for a test environment where they
control the secret → `create --claim role=admin ...`, not `exploit` (no
vulnerability being demonstrated, just a normal signed token).

**"Is this token/API exploitable?"** → `decode` first to see `alg`, then
`crack <token>` offline, then `crack <token> --url <target> [--key pub.pem]`
if they've confirmed authorization to test the live endpoint. Report the
findings; only escalate to a specific `exploit` subcommand if they want a
standalone repro token to hand off separately.

**"Bypass auth on this endpoint using this token"** (CTF/pentest context) →
run `crack --url` first to see which techniques the server actually accepts,
then use the matching `exploit` subcommand to produce the final token if
`crack`'s report doesn't already hand you one.

**"Does this app accept a null-signed / alg=none token?"** → `exploit
nullsig` / `exploit algnone` to produce the token, then let the user (or you,
if they've asked you to) replay it against their endpoint with curl.
