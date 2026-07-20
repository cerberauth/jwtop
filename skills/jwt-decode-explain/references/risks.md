# JWT risk catalog — decode-time signals

Everything here is detectable from header/claims alone, no key or network
call needed. Severity is about how bad it is *if the server also gets the
corresponding check wrong* — decoding never proves the server is
vulnerable, only that the token creates the opportunity.

## Header risks

### `alg` = `none` (any casing: `none`, `None`, `NONE`)
**Severity: high, if a live server would ever accept it.**
A JWT library that honors `alg=none` skips signature verification entirely
— anyone can edit claims and re-encode with no signature at all. Purely
decoding a token that already has `alg=none` doesn't prove a server accepts
it, but it means the token was likely produced specifically to test that
question (see `jwtop exploit algnone` / `jwtop crack` in the `jwtop` skill).

### `alg` = `HS256`/`HS384`/`HS512` on a token that "should" be asymmetric
**Severity: informational at decode time.**
Algorithm confusion (RS/HS key confusion, CVE-style bugs) happens when a
server expects `RS256` (verifies with a *public* key) but a JWT library
lets an attacker submit `HS256` instead, so the server ends up using its own
public key as an HMAC secret. Decoding alone can't tell you the server is
misconfigured this way — only that the token you're holding is HMAC-signed.
Worth a note if the ecosystem context (an OIDC token, an RS256-issuing
platform) makes HS256 look out of place.

### `jwk`, `jku`, or `x5u`/`x5c` present in the header
**Severity: high.**
These fields let the token *hand the verifier its own key material or a URL
to fetch a key from*. A verifier that blindly trusts an embedded `jwk` or
fetches whatever URL is in `jku`/`x5u` will happily verify a token signed
with an attacker-controlled key. Presence of any of these fields is worth
flagging regardless of what `alg` says, since it changes where the trust
anchor comes from.

### `kid` (key ID) shaped like a path, filename, or SQL fragment
**Severity: medium (smell, not proof).**
Some verifiers use `kid` to look up a key — from a filesystem path, a
database row, or a URL — without sanitizing it first. A `kid` value like
`../../../../dev/null`, `' OR '1'='1`, or a full URL is a sign the token may
have been crafted to test kid-injection, even though decoding alone can't
confirm the server is vulnerable.

### `typ` missing or not `JWT`
**Severity: informational.**
Rarely meaningful by itself; note it only if something else about the token
looks off.

## Claims risks

### `exp` missing entirely
**Severity: high for anything representing a live session or bearer
credential.**
No `exp` claim means the token has no built-in expiration — if the server
doesn't separately track a lifetime, this token is valid forever once
issued. Say this plainly: "no `exp` claim, so this token doesn't expire on
its own."

### `exp` set implausibly far in the future
**Severity: medium–high depending on context.**
A token expiring in 10 years functions the same as one that never expires.
Compare to what you'd expect for the token's apparent purpose (a
short-lived API access token vs. a long-lived refresh token/API key)
before deciding how alarming this is.

### `iat` far in the past relative to `exp`, or absent
**Severity: informational.**
Missing `iat` isn't itself a vulnerability, but makes it harder to reason
about how long a token has been alive, which matters for revocation and
replay discussions.

### Sensitive-looking values in claims (emails, names, internal IDs, secrets)
**Severity: medium, always worth stating once.**
A JWT's payload is base64url-*encoded*, not encrypted — anyone who
intercepts the token (logs, browser history, a proxy, a shared machine) can
read every claim in plaintext. This is true of the *most innocuous* token
too; it's a property of the format, not a bug in this specific token. Flag
it whenever claims contain anything a user might assume is private.

### `aud`/`iss` present but "you can't tell if they're checked"
**Severity: informational, always worth one line.**
A decoded token can show you what it *claims* to be issued by/for, but
proves nothing about whether the relying service actually validates those
fields. Don't let a plausible-looking `iss`/`aud` read as reassuring by
itself.

## What decoding can never tell you

- Whether the signature is valid (`jwtop verify` with the actual
  secret/key/JWKS answers this)
- Whether the server enforces `exp`/`aud`/`iss` at all
- Whether `alg=none`, key confusion, or kid injection actually work against
  a live server (`jwtop crack`/`exploit` answer this, with authorization)

Always separate "this is what the token claims" from "this is what's been
verified."
