package scopenotvalidated_test

import (
	"testing"

	"github.com/cerberauth/jwtop/jwt/crack/checkbase"
	scopenotvalidated "github.com/cerberauth/jwtop/jwt/crack/checks/scope_not_validated"
	"github.com/cerberauth/jwtop/jwt/crack/internal/claimtest"
	jwtlib "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

func TestCheck(t *testing.T) {
	requiresScope := func(c jwtlib.MapClaims) bool { return c["scope"] == "read" && c["roles"] != nil }
	ignoresScope := func(jwtlib.MapClaims) bool { return true }
	token := claimtest.Sign(t, jwtlib.MapClaims{"sub": "1", "scope": "read", "roles": []string{"admin"}})

	testCases := []struct {
		name       string
		accept     func(jwtlib.MapClaims) bool
		token      string
		vulnerable bool
		skipped    bool
	}{
		{"scope validated", requiresScope, token, false, false},
		{"scope ignored", ignoresScope, token, true, false},
		{"no scope claim", ignoresScope, claimtest.Sign(t, jwtlib.MapClaims{"sub": "1"}), false, true},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			pr, reason := claimtest.Run(t, scopenotvalidated.Check, claimtest.Server(t, tc.accept), &checkbase.ProbeCtx{TokenString: tc.token, CrackedHMACSecret: string(claimtest.Secret)})

			assert.Equal(t, tc.skipped, reason != "", reason)
			assert.Equal(t, tc.vulnerable, pr.Vulnerable)
		})
	}
}
