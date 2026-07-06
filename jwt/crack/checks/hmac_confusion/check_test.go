package hmacconfusion_test

import (
	"context"
	"testing"

	"github.com/cerberauth/harnessx"
	"github.com/stretchr/testify/assert"

	"github.com/cerberauth/jwtop/jwt/crack/checkbase"
	hmacconfusion "github.com/cerberauth/jwtop/jwt/crack/checks/hmac_confusion"
)

func TestCheck_Skip_Offline(t *testing.T) {
	store := harnessx.NewStaticResultStore()
	target := harnessx.Target{Data: &checkbase.ProbeCtx{Offline: true, IsAsymmetric: true, PublicKeyPEM: []byte("pem")}}

	reason := hmacconfusion.Check.Skip.Eval(context.Background(), target, store)
	assert.NotEmpty(t, reason)
}

func TestCheck_Skip_NotAsymmetric(t *testing.T) {
	store := harnessx.NewStaticResultStore()
	target := harnessx.Target{Data: &checkbase.ProbeCtx{IsAsymmetric: false, Alg: "HS256", PublicKeyPEM: []byte("pem")}}

	reason := hmacconfusion.Check.Skip.Eval(context.Background(), target, store)
	assert.NotEmpty(t, reason)
}

func TestCheck_Skip_NoPublicKey(t *testing.T) {
	store := harnessx.NewStaticResultStore()
	target := harnessx.Target{Data: &checkbase.ProbeCtx{IsAsymmetric: true, PublicKeyPEM: nil}}

	reason := hmacconfusion.Check.Skip.Eval(context.Background(), target, store)
	assert.NotEmpty(t, reason)
}

func TestCheck_Skip_RunsWhenAsymmetricAndPublicKeyPresent(t *testing.T) {
	store := harnessx.NewStaticResultStore()
	target := harnessx.Target{Data: &checkbase.ProbeCtx{IsAsymmetric: true, PublicKeyPEM: []byte("pem")}}

	reason := hmacconfusion.Check.Skip.Eval(context.Background(), target, store)
	assert.Empty(t, reason)
}
