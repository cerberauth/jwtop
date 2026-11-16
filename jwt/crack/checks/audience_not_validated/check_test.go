package audiencenotvalidated_test

import (
	"testing"

	"github.com/cerberauth/jwtop/jwt/crack/checkbase"
	audiencenotvalidated "github.com/cerberauth/jwtop/jwt/crack/checks/audience_not_validated"
	"github.com/cerberauth/jwtop/jwt/crack/internal/claimtest"
	jwtlib "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

func TestCheck(t *testing.T) {
	validatesAud := func(c jwtlib.MapClaims) bool { return c["aud"] == "api" }
	ignoresAud := func(jwtlib.MapClaims) bool { return true }
	token := claimtest.Sign(t, jwtlib.MapClaims{"sub": "1", "aud": "api"})
	otherToken := claimtest.Sign(t, jwtlib.MapClaims{"sub": "1", "aud": "billing"})

	testCases := []struct {
		name       string
		accept     func(jwtlib.MapClaims) bool
		pctx       checkbase.ProbeCtx
		vulnerable bool
		skipped    bool
	}{
		{"other token rejected", validatesAud, checkbase.ProbeCtx{TokenString: token, OtherAudienceToken: otherToken}, false, false},
		{"other token accepted", ignoresAud, checkbase.ProbeCtx{TokenString: token, OtherAudienceToken: otherToken}, true, false},
		{"re-signed aud rejected", validatesAud, checkbase.ProbeCtx{TokenString: token, CrackedHMACSecret: string(claimtest.Secret)}, false, false},
		{"re-signed aud accepted", ignoresAud, checkbase.ProbeCtx{TokenString: token, CrackedHMACSecret: string(claimtest.Secret)}, true, false},
		{"no other token nor key", ignoresAud, checkbase.ProbeCtx{TokenString: token}, false, true},
		{"no aud claim", ignoresAud, checkbase.ProbeCtx{TokenString: claimtest.Sign(t, jwtlib.MapClaims{"sub": "1"}), CrackedHMACSecret: string(claimtest.Secret)}, false, true},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			pctx := tc.pctx
			pr, reason := claimtest.Run(t, audiencenotvalidated.Check, claimtest.Server(t, tc.accept), &pctx)

			assert.Equal(t, tc.skipped, reason != "", reason)
			assert.Equal(t, tc.vulnerable, pr.Vulnerable)
		})
	}
}

func TestCheck_SkipOffline(t *testing.T) {
	_, reason := claimtest.Run(t, audiencenotvalidated.Check, "", &checkbase.ProbeCtx{OtherAudienceToken: "token"})

	assert.Equal(t, "requires live server", reason)
}
