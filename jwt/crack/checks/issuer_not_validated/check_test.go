package issuernotvalidated_test

import (
	"testing"

	"github.com/cerberauth/jwtop/jwt/crack/checkbase"
	issuernotvalidated "github.com/cerberauth/jwtop/jwt/crack/checks/issuer_not_validated"
	"github.com/cerberauth/jwtop/jwt/crack/internal/claimtest"
	jwtlib "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

func TestCheck(t *testing.T) {
	validatesIss := func(c jwtlib.MapClaims) bool { return c["iss"] == "idp" }
	ignoresIss := func(jwtlib.MapClaims) bool { return true }
	token := claimtest.Sign(t, jwtlib.MapClaims{"sub": "1", "iss": "idp"})
	otherToken := claimtest.Sign(t, jwtlib.MapClaims{"sub": "1", "iss": "other-idp"})

	testCases := []struct {
		name       string
		accept     func(jwtlib.MapClaims) bool
		pctx       checkbase.ProbeCtx
		vulnerable bool
		skipped    bool
	}{
		{"other token rejected", validatesIss, checkbase.ProbeCtx{TokenString: token, OtherIssuerToken: otherToken}, false, false},
		{"other token accepted", ignoresIss, checkbase.ProbeCtx{TokenString: token, OtherIssuerToken: otherToken}, true, false},
		{"re-signed iss rejected", validatesIss, checkbase.ProbeCtx{TokenString: token, CrackedHMACSecret: string(claimtest.Secret)}, false, false},
		{"re-signed iss accepted", ignoresIss, checkbase.ProbeCtx{TokenString: token, CrackedHMACSecret: string(claimtest.Secret)}, true, false},
		{"no other token nor key", ignoresIss, checkbase.ProbeCtx{TokenString: token}, false, true},
		{"no iss claim", ignoresIss, checkbase.ProbeCtx{TokenString: claimtest.Sign(t, jwtlib.MapClaims{"sub": "1"}), CrackedHMACSecret: string(claimtest.Secret)}, false, true},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			pctx := tc.pctx
			pr, reason := claimtest.Run(t, issuernotvalidated.Check, claimtest.Server(t, tc.accept), &pctx)

			assert.Equal(t, tc.skipped, reason != "", reason)
			assert.Equal(t, tc.vulnerable, pr.Vulnerable)
		})
	}
}

func TestCheck_SkipOffline(t *testing.T) {
	_, reason := claimtest.Run(t, issuernotvalidated.Check, "", &checkbase.ProbeCtx{OtherIssuerToken: "token"})

	assert.Equal(t, "requires live server", reason)
}
