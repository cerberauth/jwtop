package baseline_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"

	jwtlib "github.com/golang-jwt/jwt/v5"

	"github.com/cerberauth/harnessx"
	"github.com/stretchr/testify/assert"

	"github.com/cerberauth/jwtop/jwt/crack/checkbase"
	"github.com/cerberauth/jwtop/jwt/crack/checks/baseline"
)

func TestCheck_Run_Offline_PopulatesProbeCtx(t *testing.T) {
	tok := jwtlib.NewWithClaims(jwtlib.SigningMethodHS256, jwtlib.MapClaims{"sub": "user1"})
	tokenString, err := tok.SignedString([]byte("secret"))
	assert.NoError(t, err)

	store := harnessx.NewStaticResultStore()
	pctx := &checkbase.ProbeCtx{TokenString: tokenString, Offline: true}
	target := harnessx.Target{Data: pctx}

	result, err := baseline.Check.Run(context.Background(), target, store)
	assert.NoError(t, err)

	status, ok := harnessx.DataAs[int](result)
	assert.True(t, ok)
	assert.Equal(t, 0, status)

	assert.Equal(t, "HS256", pctx.Alg)
	assert.True(t, pctx.IsHMAC)
	assert.False(t, pctx.IsAsymmetric)
	assert.True(t, strings.HasSuffix(pctx.InvalidToken, ".invalidsignature"))
	assert.Len(t, pctx.AlgNoneTokens, 4)
	assert.NoError(t, pctx.AlgNoneErr)
}

func TestCheck_Run_Offline_AsymmetricAlg(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)
	tok := jwtlib.NewWithClaims(jwtlib.SigningMethodRS256, jwtlib.MapClaims{"sub": "user1"})
	tokenString, err := tok.SignedString(key)
	assert.NoError(t, err)

	store := harnessx.NewStaticResultStore()
	pctx := &checkbase.ProbeCtx{TokenString: tokenString, Offline: true}
	target := harnessx.Target{Data: pctx}

	_, err = baseline.Check.Run(context.Background(), target, store)
	assert.NoError(t, err)

	assert.False(t, pctx.IsHMAC)
	assert.True(t, pctx.IsAsymmetric)
}
