package longlifetime_test

import (
	"testing"
	"time"

	"github.com/cerberauth/jwtop/jwt/crack/checkbase"
	longlifetime "github.com/cerberauth/jwtop/jwt/crack/checks/long_lifetime"
	"github.com/cerberauth/jwtop/jwt/crack/internal/claimtest"
	jwtlib "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

func TestCheck(t *testing.T) {
	now := time.Now()
	testCases := []struct {
		name        string
		claims      jwtlib.MapClaims
		maxLifetime time.Duration
		vulnerable  bool
		skipped     bool
	}{
		{"short lifetime", jwtlib.MapClaims{"iat": now.Unix(), "exp": now.Add(time.Hour).Unix()}, 0, false, false},
		{"above default", jwtlib.MapClaims{"iat": now.Unix(), "exp": now.Add(30 * 24 * time.Hour).Unix()}, 0, true, false},
		{"above configured", jwtlib.MapClaims{"iat": now.Unix(), "exp": now.Add(2 * time.Hour).Unix()}, time.Hour, true, false},
		{"without iat", jwtlib.MapClaims{"exp": now.Add(48 * time.Hour).Unix()}, 0, true, false},
		{"without exp", jwtlib.MapClaims{"sub": "1"}, 0, false, true},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			pr, reason := claimtest.Run(t, longlifetime.Check, "", &checkbase.ProbeCtx{TokenString: claimtest.Sign(t, tc.claims), MaxTokenLifetime: tc.maxLifetime})

			assert.Equal(t, tc.skipped, reason != "", reason)
			assert.Equal(t, tc.vulnerable, pr.Vulnerable)
		})
	}
}
