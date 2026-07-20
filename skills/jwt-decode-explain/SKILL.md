---
name: jwt-decode-explain
description: Decode a JWT's header and claims and explain in plain language what's inside and which parts make it risky — alg=none, weak/guessable HMAC secrets, RS/HS key-confusion, embedded jwk/jku/x5u header injection, kid injection, missing or absurdly long exp, sensitive PII sitting in claims, missing aud/iss checks. Use this whenever someone pastes a raw JWT (three base64url segments joined by dots, starts with "eyJ") and asks "what's in this token", "explain this JWT", "decode this token", "is this token safe/risky", "can I trust this token", "what does this JWT contain", or hands over a token from a support ticket, log line, browser devtools, or Authorization header and wants to understand it, not just see raw decoded JSON. Trigger even if the word "JWT" is never said, as long as the string is clearly a compact JWT. This skill is the fast educational read — decode + teach the risk. For actually running exploits, cracking secrets, forging tokens, or verifying signatures, defer to the jwtop skill instead.
---

# jwt-decode-explain

Turn a raw JWT into a plain-language explanation a developer can act on:
what's in the header, what's in the claims, and — the part that's easy to
miss — *why* specific fields make this token risky. This is a read-only,
educational pass. It never verifies a signature and never claims a token is
"valid."

## Step 1 — Decode without trusting

A JWT is `base64url(header).base64url(payload).signature` — the signature is
opaque without a key, but header and payload are always plain JSON, no
secret needed. Decoding tells you nothing about whether the token is
authentic.

If `jwtop` is on `PATH` (check `jwtop -v`; if this repo is the checkout,
`go build -o jwtop .` first), it's the fastest path:

```sh
jwtop decode <token>
```

No `jwtop` available? Decode manually — pad each segment to a multiple of 4
with `=` before base64 decoding:

```sh
python3 -c "
import base64, json, sys
def b64(s):
    s += '=' * (-len(s) % 4)
    return json.loads(base64.urlsafe_b64decode(s))
token = sys.argv[1]
h, p, _ = token.split('.')
print(json.dumps(b64(h), indent=2))
print(json.dumps(b64(p), indent=2))
" '<token>'
```

Never run `verify` or claim the signature checks out unless the user also
handed you a secret/key/JWKS *and* you actually ran the check.

## Step 2 — Present header and claims, translated

Don't just dump JSON — translate it:

**Header** — call out each field's purpose, not just its value:
- `alg` — the signing algorithm; this single field decides most of the risk
  analysis in Step 3
- `typ` — almost always `JWT`, uninteresting unless absent or different
- `kid` — a key identifier; interesting because servers sometimes look it up
  unsafely (see kid injection below)
- `jku`, `jwk`, `x5u`, `x5c` — anything that hands the verifier its *own* key
  material or a URL to fetch one from; always worth flagging (Step 3)

**Claims** — translate registered claims into human terms rather than
leaving them as raw numbers:
- `exp`/`iat`/`nbf` — convert Unix timestamps to actual dates, and say how
  far in the past/future they are relative to now ("expired 3 days ago",
  "issued 11 months ago, no expiry set")
- `iss`/`aud`/`sub` — state what they claim to identify, but note the app
  still has to *check* these against expected values; a decoded token
  matching what you'd expect proves nothing about verification
- `jti` — token ID, relevant for replay/revocation discussions
- Anything else — call it a custom/app-specific claim, and skim the values
  for anything that looks like it shouldn't be sitting in a token readable
  by anyone who intercepts it (see PII below)

## Step 3 — Explain the risk, don't just flag it

Cross-check against `references/risks.md` for the full catalog with
severity and reasoning. The goal is teaching *why*, not producing a bare
checklist — a dev who understands why `alg=none` is catastrophic will catch
the next instance themselves; a dev handed "⚠️ alg=none" without context
won't.

At minimum, check:
1. **`alg`** — `none` (any casing) is a broken-auth bug by itself if a
   server ever accepts it. `HS256` on a token whose claims suggest it should
   be asymmetric is a lower-severity note (key confusion is only exploitable
   if the server misconfigures verification, not from decoding alone).
2. **Header injection fields** — `jwk`, `jku`, or `x5u` present in the
   header means the token is *supplying its own trust anchor*; flag high
   severity regardless of `alg`.
3. **`kid`** — does the value look like a filename, path, or SQL fragment
   rather than a short opaque ID? That's a smell even without proving
   exploitability.
4. **`exp`** — missing entirely, or set implausibly far out (years), means
   the token effectively never expires — high severity for anything
   representing a live session.
5. **Claim contents** — emails, names, internal IDs, or anything
   secret-shaped sitting in plaintext claims is a reminder that JWTs are
   *signed, not encrypted* — anyone holding the token can read this.
6. **Missing `aud`/`iss`** — not a token defect by itself, but worth one
   line noting the *receiving service* must still validate these; a
   decoded token can't tell you whether it does.

## Step 4 — Structure the answer

Use three short sections so the user can scan it:

```
## Header
<translated fields>

## Claims
<translated fields, with computed exp/iat context>

## Risk notes
- [severity] finding — why it matters
- [severity] finding — why it matters
(or: "Nothing structurally alarming in the header/claims — remember
decoding still doesn't prove the signature is valid.")
```

Always end with a one-line reminder that decode ≠ verify, restated in
context of what was just shown (e.g. "This confirms what the token
*claims*; whether `billing-service` actually signed it is a separate
question — run `jwtop verify` with the signing key/secret to check").

## Where this differs from `jwtop`'s own `decode`

`jwtop decode` (see the `jwtop` skill) is the raw print — header, claims,
signature, nothing else. This skill wraps that same primitive with the
explanation layer: translated fields, computed time deltas, and a taught
risk narrative. If the user's ask is purely mechanical ("just show me the
JSON"), a plain `jwtop decode` is enough and this skill's extra structure is
overhead — use judgment on how much explanation the question actually
calls for.
