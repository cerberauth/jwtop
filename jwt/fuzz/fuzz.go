// Package fuzz generates claim-mutation payloads for the "jwtop crack
// --fuzz" mode: type confusion, oversized strings, special characters, and
// explicit nulls applied to each claim of a JWT, so a live server can be
// probed for parsing bugs (crashes, stack traces, wildly different
// response sizes) that the fixed check set in jwt/crack/checks/ doesn't
// exercise. It complements, rather than replaces, those checks.
package fuzz
