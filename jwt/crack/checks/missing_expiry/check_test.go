package missingexpiry_test

import (
	"testing"
	"time"

	"github.com/cerberauth/jwtop/jwt/crack/checkbase"
	missingexpiry "github.com/cerberauth/jwtop/jwt/crack/checks/missing_expiry"
	"github.com/cerberauth/jwtop/jwt/crack/internal/claimtest"
	jwtlib "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

func TestCheck(t *testing.T) {
	testCases := []struct {
		name       string
		claims     jwtlib.MapClaims
		vulnerable bool
	}{
		{"with exp", jwtlib.MapClaims{"sub": "1", "exp": time.Now().Add(time.Hour).Unix()}, false},
		{"without exp", jwtlib.MapClaims{"sub": "1"}, true},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			pr, reason := claimtest.Run(t, missingexpiry.Check, "", &checkbase.ProbeCtx{TokenString: claimtest.Sign(t, tc.claims)})

			assert.Empty(t, reason)
			assert.Equal(t, tc.vulnerable, pr.Vulnerable)
		})
	}
}
