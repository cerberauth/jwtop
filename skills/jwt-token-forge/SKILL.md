---
name: jwt-token-forge
description: Turn a plain-language token spec (claims, algorithm, key type) into a working `jwtop create`/`sign` invocation that mints a real, correctly-signed test JWT — including generating an RSA/EC keypair with openssl when the user doesn't already have one, and handling `alg=none` (which `jwtop create` refuses directly, so it goes through `create` then `sign --alg none`). Use this whenever the user wants a synthetic/test/fixture JWT for their own test suite, staging environment, or local dev — phrases like "generate a test JWT with claims X", "give me an RS256 token with sub=user123", "make me a token that expires in 5 minutes", "I need a fixture JWT for role=admin", or "sign a token with an EC key for my ES256 tests". This is about minting a clean token from a spec, not about mutating or attacking an existing captured token (no vulnerability is being demonstrated) — for that latter case, or for full JWT lifecycle work (decode/verify/crack/exploit), the `jwtop` skill's `create`/`sign` sections may also apply; either is fine to reach for.
---

# jwt-token-forge

Turns a spec — claims, algorithm, key type — into a real signed JWT via the
`jwtop` CLI (`github.com/cerberauth/jwtop`). The interesting part isn't the
CLI call itself, it's the two things that trip people up: **picking/generating
the right key for the algorithm family**, and **`alg=none` isn't a direct
`create` option**.

Assume `jwtop` is already on `PATH`, same as any other CLI (`git`, `curl`).
If `jwtop -v` fails: inside a checkout of this repo, `go build -o jwtop .`;
elsewhere, `go install github.com/cerberauth/jwtop@latest`.

## Workflow

1. **Read the spec** the user gave you: which claims, which algorithm, and
   whether they already have a secret/key or need one generated.
2. **Resolve the key.** See the matrix below — HMAC just needs a secret
   string, RSA/EC families need a PEM keypair. If the user hasn't handed you
   an existing key/secret, generate one (openssl commands below) rather than
   asking them to go do it — that's the whole point of this skill.
3. **Map claims to flags.** `--claim key=value` for anything custom
   (repeatable), dedicated flags for `sub`/`iss`/`aud`/`exp`/`iat`.
4. **Handle `alg=none` as a special case** — see below, it's not a plain
   `create --alg none`.
5. **Run it, hand back the token.** `jwtop create`/`sign` print the token
   alone to stdout — nothing else to parse out.

## Algorithm → key type

| Algorithm(s) | Key needed | Generate if missing |
|---|---|---|
| `HS256`, `HS384`, `HS512` | HMAC secret (any string) | Just pick one — a plain string via `--secret`, no file needed. For a fixture that shouldn't be guessable, `openssl rand -hex 32` |
| `RS256`, `RS384`, `RS512` | RSA private key, PEM | `openssl genrsa -out private.pem 2048` |
| `PS256`, `PS384`, `PS512` | RSA private key, PEM (same family as RS*, different padding) | Same as RS* — `openssl genrsa -out private.pem 2048` works for both |
| `ES256` | EC private key, P-256 | `openssl ecparam -name prime256v1 -genkey -noout -out private.pem` |
| `ES384` | EC private key, P-384 | `openssl ecparam -name secp384r1 -genkey -noout -out private.pem` |
| `ES512` | EC private key, P-521 | `openssl ecparam -name secp521r1 -genkey -noout -out private.pem` |
| `none` | none — but see below, `create` won't take it directly | — |

`--key` also accepts a URL, fetched over HTTP — useful if the user already
has a key published somewhere, but for a fresh test fixture generating a
local PEM is almost always what they want.

`jwtop` itself has no keygen subcommand (there's a `GenerateKey` helper in
the Go source, but nothing wired up to the CLI) — openssl is the tool for
this, not `jwtop`.

## Claims → flags

| Claim source | Flag | Notes |
|---|---|---|
| Custom claim | `--claim key=value` | Repeatable. Values auto-coerce: `role=admin` → string, `count=5` → int64, `flag=true`/`false` → bool. Quote values with `=` or spaces. |
| `sub` | `--sub <value>` | Overrides a `--claim sub=...` if both given |
| `iss` | `--iss <value>` | Same override behavior |
| `aud` | `--aud <value>` | Same override behavior |
| `exp` | `--exp <duration>` | Relative to now — `1h`, `30m`, `15s`, `24h`. Sets the numeric `exp` claim, doesn't take an absolute timestamp. |
| `iat` | `--iat` | Boolean flag, no value — include current time as issued-at |

There's no `--nbf` flag on `create` even though the underlying Go library
supports not-before — if the user specifically needs `nbf`, use `--claim
nbf=<unix-timestamp>` instead.

## `alg=none` is a two-step

`jwtop create --alg none` **fails** — the underlying JWT library refuses to
mint a `none`-signed token from scratch (`'none' signature type is not
allowed`). To get one, create a normal token first with any throwaway
alg/secret, then re-sign it to `none`:

```sh
TOKEN=$(jwtop create --alg HS256 --secret throwaway --sub user123 --claim role=admin)
jwtop sign "$TOKEN" --alg none
```

`sign --alg none` strips the signature but keeps every claim from the first
step — so put the real claims in the `create` call, not the `sign` call
(`sign` takes no claim flags at all, it only changes how the token is signed).

## Worked examples

**"Generate a test JWT, HS256, sub=user123, role=admin, plan=pro, expires in
1 hour, include issued-at"**

```sh
jwtop create --alg HS256 --secret mysecret \
  --sub user123 --exp 1h --iat \
  --claim role=admin --claim plan=pro
```

**"I need an RS256 token for my test suite, no key yet, claims iss=myapp,
sub=user123"**

```sh
openssl genrsa -out private.pem 2048
jwtop create --alg RS256 --key private.pem --iss myapp --sub user123
```

**"Sign a fixture with ES384 for my ECDSA verification tests"**

```sh
openssl ecparam -name secp384r1 -genkey -noout -out ec384-private.pem
jwtop create --alg ES384 --key ec384-private.pem --sub testuser
```

**"Give me a token with no signature at all, alg none, claims sub=x"**

```sh
TOKEN=$(jwtop create --alg HS256 --secret throwaway --sub x)
jwtop sign "$TOKEN" --alg none
```

## Verifying what you minted

If the user (or you) wants to sanity-check the result before handing it
back, `jwtop decode <token>` prints header/claims without needing the
key/secret, and `jwtop verify <token> --secret ...` / `--key ...` confirms
the signature actually checks out against the key you just used.
