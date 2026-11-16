package claimremoval_test

import (
	"testing"
	"time"

	"github.com/cerberauth/jwtop/jwt/crack/checkbase"
	claimremoval "github.com/cerberauth/jwtop/jwt/crack/checks/claim_removal"
	"github.com/cerberauth/jwtop/jwt/crack/internal/claimtest"
	jwtlib "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

func requires(names ...string) func(jwtlib.MapClaims) bool {
	return func(c jwtlib.MapClaims) bool {
		for _, name := range names {
			if _, ok := c[name]; !ok {
				return false
			}
		}
		return true
	}
}

func TestCheck(t *testing.T) {
	now := time.Now()
	token := claimtest.Sign(t, jwtlib.MapClaims{"iss": "idp", "aud": "api", "sub": "1", "exp": now.Add(time.Hour).Unix(), "nbf": now.Unix(), "iat": now.Unix()})

	testCases := []struct {
		name       string
		accept     func(jwtlib.MapClaims) bool
		vulnerable bool
		extra      string
	}{
		{"every claim required", requires(claimremoval.RegisteredClaims...), false, ""},
		{"aud not required", requires("iss", "sub", "exp", "nbf", "iat"), true, "variant: aud"},
		{"no claim required", requires(), true, "variant: iss"},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			pr, reason := claimtest.Run(t, claimremoval.Check, claimtest.Server(t, tc.accept), &checkbase.ProbeCtx{TokenString: token, CrackedHMACSecret: string(claimtest.Secret)})

			assert.Empty(t, reason)
			assert.Equal(t, tc.vulnerable, pr.Vulnerable)
			if tc.extra != "" {
				assert.Equal(t, tc.extra, pr.Extra)
			}
		})
	}
}

func TestCheck_SkipWithoutSigningKey(t *testing.T) {
	_, reason := claimtest.Run(t, claimremoval.Check, claimtest.Server(t, requires()), &checkbase.ProbeCtx{TokenString: claimtest.Sign(t, jwtlib.MapClaims{"sub": "1"})})

	assert.Contains(t, reason, "signing key unknown")
}

func TestCheck_UsesSigningKey(t *testing.T) {
	token := claimtest.Sign(t, jwtlib.MapClaims{"sub": "1"})

	pr, reason := claimtest.Run(t, claimremoval.Check, claimtest.Server(t, requires()), &checkbase.ProbeCtx{TokenString: token, SigningKey: claimtest.Secret})

	assert.Empty(t, reason)
	assert.True(t, pr.Vulnerable)
}
