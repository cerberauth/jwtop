# Remediation reference — one entry per `crack` finding

Each entry: what the finding means, why it's exploitable, and the fix.
Full writeups with worked examples live at
`https://www.cerberauth.com/docs/jwtop/vulnerabilities/<slug>` (linked
below) if the user wants more than a summary.

## Algorithm None — CWE-345, CVSS 9.3

**Slug:** `jwt-alg-none`

Fires when the server accepts a token with `alg` rewritten to `none` (or a
casing variant: `None`, `NONE`, `nOnE`) and the signature segment emptied.
Some JWT libraries treat `none` as a legitimate "unsecured JWT" mode per
the spec and skip verification entirely if the caller doesn't explicitly
opt out of it.

**Fix:**
- Update the JWT library to a version that patches this if it's an old
  known-vulnerable one; check for security advisories from the maintainer.
- Configure the library to enforce an algorithm allowlist and explicitly
  reject `none` — don't rely on the library's default behavior.

## No Verification — CWE-345, CVSS 9.3

**Slug:** `jwt-signature-not-verified`

Fires when the server accepts a token whose signature was never actually
checked — the app decoded the payload and trusted it without calling a
verify function at all.

**Fix:**
1. Always call the library's verification function, never a decode-only
   call, on any token used for auth decisions.
2. Pass the expected public key (RS/ES) or secret (HS) explicitly — never
   let the library auto-detect the key from the token's own header.
3. Pin the allowed algorithm set (e.g. `["RS256"]`) so verification can't
   silently degrade to something weaker.
4. Prefer asymmetric algorithms (RS256/ES256) for distributed systems —
   only the issuer holds the private key, every verifier just needs the
   public key.

## Null Signature — CWE-345, CVSS 9.3

**Slug:** `jwt-null-signature`

Fires when the server accepts the token's original `alg` header but with
the signature segment stripped to empty (`header.payload.`). Distinct from
Algorithm None: the header claims a real algorithm was used, but nothing
was actually checked.

**Fix:**
- Verify every token with a real cryptographic check before trusting any
  claim in it — never accept an empty/missing signature regardless of what
  `alg` says.
- Use a strong algorithm (HS512/RS512/ES512 or better) and keep the
  signing key confidential.
- Add monitoring/alerting on repeated verification failures — a spike is a
  signal someone's probing for this exact gap.

## Blank Secret — CWE-345, CVSS 9.3

**Slug:** `jwt-blank-secret`

Fires when the server accepts an HS*-signed token that was re-signed using
an empty string `""` as the HMAC secret — i.e. the signing secret was
never actually configured, or a misconfiguration left it blank.

**Fix:**
- Ensure every HS* verifier is configured with a real, non-empty secret;
  fail startup/config validation if the secret is empty rather than
  silently accepting it.
- Use a strong cryptographic algorithm and keep the secret confidential.

## Weak Secret — CWE-345, CVSS 9.3

**Slug:** `jwt-weak-secret`

Fires when an HS* token's signing secret is guessable — either a common
value (`secret`, `password`, `123456`), a framework/library default, or
short enough for a dictionary attack to land. `crack`'s offline check
already ran the built-in wordlist (from SecLists) plus any `--wordlist`/
`--secret` values supplied; if it fired, the report/`--format json` output
carries the actual recovered secret in `findings[].extra.detail`.

**Fix:**
- Rotate to a strong, unique secret generated with a secure random source
  (256 bits of entropy for HS256, more for HS384/512) — not a
  human-chosen phrase.
- Store it in a secrets manager, not source control or a config default.
- Rotate periodically, and immediately if this audit recovered the current
  one — treat a cracked secret as already compromised.

## HMAC Confusion — CWE-345 / CWE-327, CVSS 9.3

**Slug:** `jwt-hmac-confusion`

Fires when the server, configured for an asymmetric algorithm (RS*/ES*/
PS*) and holding a public key for verification, also accepts the *same
token re-signed as the matching HS* algorithm using that public key as the
HMAC secret*. This works when the verification code picks its behavior
from the token's own `alg` header — see `alg: HS256`, treat whatever key
material is on hand as an HMAC secret — without checking that the key
being used is actually meant to be symmetric.

**Fix:**
- **Algorithm pinning**: configure the library to accept *only* the
  intended algorithm (e.g. `RS256` only) rather than trusting the token's
  header to pick it.
- **Key-type validation**: never let key material meant for asymmetric use
  (a public key) get used in an HMAC operation.
- **Separate verification paths**: don't use one generic "verify" function
  that branches on the token's claimed algorithm.

## Psychic Signature — CWE-347, CVSS 9.3, CVE-2022-21449

**Slug:** `jwt-psychic-signature`

Only relevant to ES256/384/512 tokens. Fires when the server accepts a
signature replaced with an all-zero `r=0, s=0` pair — some ECDSA verifiers
(notably Java's SunEC provider in JDK 15–18 before the patch) fail to
reject this degenerate signature and treat it as valid for *any* message
and *any* public key.

**Fix:**
- Patch the JDK to a version with the fix (18.0.1, 17.0.3, 15.0.7, or
  later) if the verifier runs on a vulnerable JDK.
- If implementing/auditing ECDSA verification directly, explicitly check
  `r` and `s` are both in range `[1, n-1]` — never zero — before use.
- Cross-check custom crypto code against Project Wycheproof's test
  vectors for this class of bug rather than trusting ad hoc validation.
- Defense in depth: still validate `iss`/`aud`/`exp` even when signature
  checks pass, and consider algorithm/key pinning.

## KID SQL Injection — CWE-89 (via CWE-345 in the report), CVSS 9.3

**Slug:** `jwt-kid-injection`

Fires when the server looks up verification key material from a database
using the token's `kid` header value directly in a query, letting an
attacker craft a `kid` that manipulates the query to return an
attacker-known value — which the attacker then uses as the signing secret.

**Fix:**
- Validate `kid` before using it in any lookup — reject values with SQL
  metacharacters or anything outside a safe allowlist (alphanumeric and
  hyphens, say).
- Use parameterized queries for any `kid`-based database lookup — never
  string-concatenate the header value into SQL.
- Prefer a hard-coded/allowlisted set of permitted `kid` values over
  dynamic lookup where the key set is small and known.

## KID Path Traversal — CWE-22 (via CWE-345 in the report), CVSS 9.3

**Slug:** `jwt-kid-injection`

Fires when the server reads key material from a filesystem path built from
the token's `kid` header, letting an attacker point `kid` at a file with
predictable/empty contents (`/dev/null` reads as empty, which resolves to
an empty signing secret the attacker can trivially forge against).

**Fix:**
- Never read key material from a user-controlled file path — store keys
  in a secure key store and treat `kid` purely as an opaque identifier
  mapped server-side to a known key, never as part of a path.
- Apply the same `kid` validation/allowlisting as the SQL-injection case
  above if some form of dynamic lookup is unavoidable.

## Baseline

Not a vulnerability — this is `crack`'s reference request (the original
token, or a deliberately invalid one) used to establish the HTTP status
every other online check gets diffed against. Only worth mentioning in a
writeup if the baseline itself looks wrong (e.g. the original token was
already being rejected, in which case `--expected-status` should have been
set explicitly — check the audit run used it if online findings look
suspicious).
