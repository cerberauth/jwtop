---
name: jwt-security-audit
description: Run a full JWT security audit with the `jwtop crack` scanner — offline crypto checks plus, when a live endpoint is in scope, online probing — then turn the raw findings (CWE/CVSS/OWASP labels) into a plain-language verdict per vulnerability class and concrete remediation steps. Use this whenever someone asks "check this JWT for vulns", "is this token secure", "audit our JWT auth", "pentest our API's JWT handling", "what's wrong with this token", or hands over a token (and optionally an endpoint) wanting a security verdict rather than just a decode. Trigger even without the word "audit" — "is this safe to ship", "find issues with this JWT", "does this token have any weaknesses" all mean the same thing. This is the audit-and-fix skill — it runs `crack`, reads the report, and hands back a findings-plus-remediation writeup. For raw CLI mechanics across jwtop's full command set (decode/verify/create/sign/exploit), or for a pure educational read of a token's header/claims with no scan run, the `jwtop` and `jwt-decode-explain` skills cover that instead — either is fine to reach for if the ask turns out to be narrower than a full audit.
---

# jwt-security-audit

Turn a JWT (and, if in scope, the endpoint that issues/accepts it) into a
security audit: run `jwtop crack`, read what the report actually found, and
hand back a verdict per vulnerability class with a fix — not just a
pass/fail table. The scanning mechanics live in the `jwtop` skill; this
skill is about the judgment layer on top: which findings matter, why, and
what to change.

**Authorization gate — check this before anything with `--url`.** Offline
checks (no `--url`) only touch the token itself, so they're always safe to
run. The moment `--url` is on the command line, you're sending live
requests to a server. If the user's own message already establishes it's
their system, their staging environment, or a pentest engagement they're
running ("our API", "my auth service", "we run our own..."), that's enough —
don't make them repeat it. If it's unclear whether the target is
third-party, ask before probing it.

## Workflow

1. **Decode first.** `jwtop decode <token>` tells you `alg`, which
   determines which checks even apply (HMAC checks need `HS*`, hmac
   confusion needs `RS*`/`ES*`/`PS*`, psychic signature needs `ES*`
   specifically). This also catches the trivial case — `alg=none` already
   set — before you've run anything.

2. **Run the offline scan, always.** No authorization question here; it's
   pure crypto against the token you were handed:

   ```sh
   jwtop crack <token>
   jwtop crack <token> --wordlist custom.txt --secret guess1   # widen weak-secret coverage
   ```

3. **Add the online probe if an endpoint is in scope.** This is what turns
   "is this token constructed insecurely" into "does the *server* actually
   accept the insecure variant" — the real question in most audits, since a
   forgeable token that the server rejects isn't exploitable.

   ```sh
   jwtop crack <token> --url https://api.example.com/protected
   jwtop crack <token> --url https://api.example.com/protected --key public.pem   # unlocks hmacconfusion
   ```

   **A connection failure is not a finding.** If the host is unreachable
   (DNS failure, timeout, refused connection), `crack`'s baseline
   auto-detection has no real HTTP status to diff against and defaults to
   `0` — which reads as "different from the forged request's status," so
   the report can print a spurious `CRITICAL — No Verification` (or
   similar) line that has nothing to do with the server's actual security.
   Check the raw command output for a connection error before trusting any
   online finding; if you see one, the online portion of the audit simply
   didn't run — say so plainly rather than reporting the spurious finding,
   and don't retry with `--expected-status` as a fix for this case (that
   flag addresses a *reachable* server that already rejects the original
   token, not an unreachable one).

   If the token doesn't travel as a bare `Authorization: Bearer <token>`
   header — check a curl command, HAR file, or app code for how it's
   actually sent — tell `crack` where to look:

   ```sh
   --token-in cookie --token-name session
   --token-in query  --token-name access_token
   --token-in body   --token-name jwt
   ```

   `crack` auto-detects a baseline HTTP status by sending a deliberately
   invalid token; if the original token is already rejected outright, pass
   `--expected-status <code>` explicitly so the comparison has something to
   diff against.

4. **Pull the JSON report for the details that matter to a writeup.**
   `--format json` is the only format that includes the recovered
   secret/forged token in `findings[].extra.detail` — `markdown`/`html`/
   `terminal` describe *that* a check fired, not the cracked value. Run
   `crack --format json` once alongside (or instead of) whatever format the
   user wants delivered, so you have the concrete evidence to cite even if
   the final report format doesn't carry it natively.

5. **Interpret, don't just relay.** Each finding in the report carries a
   CWE ID, a CVSS 4.0 vector/score, and an OWASP API Security category —
   useful for a compliance doc, but meaningless on their own to someone
   deciding what to fix first. Translate each hit using
   `references/remediation.md`: what the finding means concretely for
   *this* token/server, why it's exploitable, and the specific code/config
   change that closes it. A report that says "Weak Secret — CVSS 9.3" is
   less useful than "the signing secret is the string `secret` — anyone can
   forge tokens with `role=admin`; rotate to a random 256-bit value and
   store it in a secrets manager."

6. **Rank before you list.** If several checks fired, lead with what's
   actually exploitable on this token (an accepted `alg=none` or cracked
   secret beats a theoretical kid-injection surface with no confirmed hit)
   rather than reciting the report in scan order.

## Reading the report: what each finding means

Full detail (attack mechanics, worked example, exact remediation) for every
check is in `references/remediation.md` — look it up by the finding name as
it appears in the `crack` report. Quick map of what triggers each and how
bad it is:

| Finding (report name) | Fires when | Severity |
|---|---|---|
| Algorithm None | Server accepts `alg` rewritten to `none`/`None`/`NONE`/`nOnE` with an empty signature | Critical — full auth bypass |
| No Verification | Server accepts a token whose signature was never checked at all | Critical — full auth bypass |
| Null Signature | Server accepts the original `alg`, but with the signature segment emptied | Critical — full auth bypass |
| Blank Secret | Server accepts an HS* token re-signed with an empty-string secret | Critical — full auth bypass |
| Weak Secret | Server (or offline check) accepts an HS* token whose secret is in a common wordlist | High — trivial forgery once the secret's known |
| HMAC Confusion | Server accepts an RS*/ES*/PS* token re-signed as the matching HS* algorithm using the public key as the HMAC secret | Critical — full auth bypass, needs the public key |
| Psychic Signature | Server accepts an ES* token with an all-zero `r=0, s=0` signature (CVE-2022-21449) | Critical where present — JDK-specific ECDSA bug |
| KID SQL Injection | Server's `kid`-based key lookup is injectable, letting the attacker control the resolved key | Critical — full auth bypass |
| KID Path Traversal | Server reads key material from a file path derived from `kid` | Critical — full auth bypass |

Only checks whose preconditions match the token's `alg` actually run online
— e.g. HMAC Confusion needs an asymmetric token plus `--key`, Psychic
Signature only applies to ES256/384/512. If a check didn't fire, confirm
it was even in scope before calling the audit clean on that front.

## Delivering the audit

Structure the final writeup as: **verdict per finding** (vulnerable /
not vulnerable / not applicable to this token's `alg`) → **why it matters
for this specific token/server** → **remediation** pulled from
`references/remediation.md`, adapted to what was actually observed (name
the concrete secret/library/config where the audit surfaced one, don't just
paste the generic advice). Close with the one or two items to fix first if
the user only acts on part of the list — usually whatever produced a
confirmed live-server hit over a theoretical/offline-only finding.

Use `jwtop crack --format markdown --output report.md` (or `html`/`sarif`)
when the user wants a shareable artifact instead of a chat reply; still do
the interpretation pass on top rather than handing over the raw report
file, since none of the exported formats include remediation text or the
cracked-secret value.
