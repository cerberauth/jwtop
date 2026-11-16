package expiredaccepted_test

import (
	"testing"
	"time"

	"github.com/cerberauth/jwtop/jwt/crack/checkbase"
	expiredaccepted "github.com/cerberauth/jwtop/jwt/crack/checks/expired_accepted"
	"github.com/cerberauth/jwtop/jwt/crack/internal/claimtest"
	jwtlib "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

func TestCheck(t *testing.T) {
	validatesExp := func(c jwtlib.MapClaims) bool {
		exp, err := c.GetExpirationTime()
		return err == nil && exp != nil && exp.After(time.Now())
	}
	ignoresExp := func(jwtlib.MapClaims) bool { return true }
	expired := claimtest.Sign(t, jwtlib.MapClaims{"sub": "1", "exp": time.Now().Add(-time.Hour).Unix()})

	testCases := []struct {
		name       string
		accept     func(jwtlib.MapClaims) bool
		token      string
		vulnerable bool
		skipped    bool
	}{
		{"expired rejected", validatesExp, expired, false, false},
		{"expired accepted", ignoresExp, expired, true, false},
		{"not expired", ignoresExp, claimtest.Sign(t, jwtlib.MapClaims{"exp": time.Now().Add(time.Hour).Unix()}), false, true},
		{"without exp", ignoresExp, claimtest.Sign(t, jwtlib.MapClaims{"sub": "1"}), false, true},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			pr, reason := claimtest.Run(t, expiredaccepted.Check, claimtest.Server(t, tc.accept), &checkbase.ProbeCtx{TokenString: tc.token})

			assert.Equal(t, tc.skipped, reason != "", reason)
			assert.Equal(t, tc.vulnerable, pr.Vulnerable)
		})
	}
}
