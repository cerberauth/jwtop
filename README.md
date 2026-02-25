[![Join Discord](https://img.shields.io/discord/1242773130137833493?label=Discord&style=for-the-badge)](https://www.cerberauth.com/community)
[![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/cerberauth/jwtop/ci.yml?branch=main&label=core%20build&style=for-the-badge)](https://github.com/cerberauth/jwtop/actions/workflows/ci.yml)
![Latest version](https://img.shields.io/github/v/release/cerberauth/jwtop?sort=semver&style=for-the-badge)
![Codecov](https://img.shields.io/codecov/c/gh/cerberauth/jwtop?token=BD1WPXJDAW&style=for-the-badge)
[![Go Report Card](https://goreportcard.com/badge/github.com/cerberauth/jwtop?style=for-the-badge)](https://goreportcard.com/report/github.com/cerberauth/jwtop)
[![GoDoc reference](https://img.shields.io/badge/godoc-reference-5272B4.svg?style=for-the-badge)](https://godoc.org/github.com/cerberauth/jwtop)
[![Github Repo Stars](https://img.shields.io/github/stars/cerberauth/jwtop?style=for-the-badge)](https://github.com/cerberauth/jwtop)
![License](https://img.shields.io/github/license/cerberauth/jwtop?style=for-the-badge)

# jwtop

JWT operations library and CLI for Go. Decode, verify, create, and sign JSON Web Tokens.

## Installation

### CLI

```sh
go install github.com/cerberauth/jwtop@latest
```

### Library

```sh
# Core operations (decode, verify, create)
go get github.com/cerberauth/jwtop/jwt

# Token editor (re-sign, mutate)
go get github.com/cerberauth/jwtop/jwt/editor
```

## CLI Usage

### decode

Decode and pretty-print a JWT without verifying the signature.

```sh
jwtop decode <token>
```

**Output:** Header, Claims, and Signature printed as formatted JSON.

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

Verify a JWT signature and print its claims. Exits with code `1` if the token is invalid.

```sh
jwtop verify <token> [--secret <secret>] [--key <pem-file>] [--jwks <uri>]
```

| Flag | Description |
|------|-------------|
| `--secret` | HMAC secret string |
| `--key` | Path to PEM public (or private) key file |
| `--jwks` | JWKS endpoint URI |

**Examples:**

```sh
# HMAC
jwtop verify $TOKEN --secret mysecret

# RSA/EC public key
jwtop verify $TOKEN --key /path/to/public.pem

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
| `--key` | Path to PEM private key file |
| `--claim key=value` | Custom claim (repeatable) |
| `--sub` | Subject claim |
| `--iss` | Issuer claim |
| `--aud` | Audience claim |
| `--exp` | Expiration duration, e.g. `1h`, `30m` |
| `--iat` | Include issued-at (`iat`) claim |

Claim values are auto-parsed: integers and booleans are stored as their native types; everything else is stored as a string.

**Examples:**

```sh
# HS256 with claims
jwtop create --alg HS256 --secret mysecret \
  --sub user123 --iss myapp --exp 1h --iat \
  --claim role=admin --claim plan=pro

# RS256 with a private key
jwtop create --alg RS256 --key /path/to/private.pem \
  --sub user123 --exp 24h
```

---

### sign

Re-sign an existing JWT with a new algorithm or key. The original claims are preserved.

```sh
jwtop sign <token> --alg <alg> (--secret <secret> | --key <pem-file>)
```

| Flag | Description |
|------|-------------|
| `--alg` | Target signing algorithm, or `none` **(required)** |
| `--secret` | HMAC secret string |
| `--key` | Path to PEM private key file |

**Examples:**

```sh
# Change algorithm and key
jwtop sign $TOKEN --alg RS256 --key /path/to/private.pem

# Strip signature (alg=none)
jwtop sign $TOKEN --alg none
```

---

### version

Print the build version.

```sh
jwtop version
```

---

## Library Usage

Import the packages you need:

```go
import (
    "github.com/cerberauth/jwtop/jwt"          // decode, verify, create
    "github.com/cerberauth/jwtop/jwt/editor"   // re-sign, mutate
)
```

### Decode

Parse a token without verifying its signature.

```go
decoded, err := jwt.Decode(tokenString)
if err != nil {
    log.Fatal(err)
}
fmt.Println(decoded.Header)    // map[string]interface{}
fmt.Println(decoded.Claims)    // map[string]interface{}
fmt.Println(decoded.Signature) // raw base64url string
```

### Verify

```go
result, err := jwt.Verify(tokenString, jwt.VerifyOptions{
    Secret: []byte("mysecret"),
    // or KeyPEM: pemBytes,
    // or JWKSURI: "https://example.com/.well-known/jwks.json",
})
if err != nil {
    log.Fatal(err) // structural error (bad token format, no key provided, etc.)
}

if result.Valid {
    fmt.Println("valid", result.Claims)
} else {
    fmt.Println("invalid:", result.Error)
}
```

`Verify` returns `(result, nil)` even when the signature is invalid — the error field is set on the result. A non-nil returned error indicates a structural problem (malformed token or missing key).

### Create

```go
tokenString, err := jwt.CreateWithSecret(jwt.CreateOptions{
    Algorithm:  "HS256",
    Claims:     map[string]string{"sub": "user123", "role": "admin"},
    Expiration: time.Hour,
    IssuedAt:   true,
}, []byte("mysecret"))

// With an asymmetric key:
tokenString, err = jwt.Create(jwt.CreateOptions{
    Algorithm: "RS256",
    Claims:    map[string]string{"sub": "user123"},
}, privateKey)
```

### TokenEditor — re-sign / mutate

`TokenEditor` (in `jwt/editor`) lets you parse an existing token (without verifying it) and re-sign it with a different algorithm or key.

```go
import (
    "github.com/cerberauth/jwtop/jwt/editor"
    jwtlib "github.com/golang-jwt/jwt/v5"
)

te, err := editor.NewTokenEditor(existingToken)
if err != nil {
    log.Fatal(err)
}

// Sign with a specific method and key
signed, err := te.SignWithMethodAndKey(jwtlib.SigningMethodHS256, []byte("newsecret"))

// Sign with the token's original algorithm and a new key
signed, err = te.SignWithKey(privateKey)

// Sign with a randomly-generated key (useful for testing)
signed, err = te.SignWithMethodAndRandomKey(jwtlib.SigningMethodRS256)

// Produce an alg=none token
signed, err = te.WithAlgNone()

// Produce a token with no signature but unchanged alg header
noSig, err := te.WithoutSignature()

// Adjust exp/nbf to make a token currently valid
valid := editor.NewTokenEditorWithValidClaims(te)
```

### Key utilities

```go
// Load keys from PEM bytes
pubKey, err  := jwt.LoadPublicKeyFromPEM(pemBytes)
privKey, err := jwt.LoadPrivateKeyFromPEM(pemBytes)

// Generate a random key for any signing method
key, err := jwt.GenerateKey(jwt.SigningMethodRS256)

// Fetch a JWKS and get a Keyfunc
keyfunc, err := jwt.FetchJWKS("https://example.com/.well-known/jwks.json")
```

### Other helpers

```go
// Parse an algorithm name to a SigningMethod
method, err := jwt.ParseSigningMethod("ES256")

// Check if a token string looks like a JWT
ok := jwt.IsJWT(tokenString)

// Check if the token's algorithm is HMAC-based (method on TokenEditor)
te, _ := editor.NewTokenEditor(tokenString)
ok = te.IsHMACAlg() // true for HS256/HS384/HS512
```

## Supported Algorithms

| Family | Algorithms |
|--------|-----------|
| HMAC | HS256, HS384, HS512 |
| RSA | RS256, RS384, RS512 |
| RSA-PSS | PS256, PS384, PS512 |
| ECDSA | ES256, ES384, ES512 |
| None | none |

## License

This repository is licensed under the [MIT License](https://github.com/cerberauth/jwtop/blob/main/LICENSE) @ [CerberAuth](https://www.cerberauth.com/). You are free to use, modify, and distribute the contents of this repository for educational and testing purposes.
