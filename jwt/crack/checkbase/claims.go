package checkbase

import (
	"context"
	"errors"
	"time"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/jwtop/jwt/editor"
	"github.com/cerberauth/jwtop/jwt/exploit"
	jwtlib "github.com/golang-jwt/jwt/v5"
)

const DefaultMaxTokenLifetime = 24 * time.Hour

func (p *ProbeCtx) ResigningKey() interface{} {
	if p.SigningKey != nil {
		return p.SigningKey
	}
	if p.IsHMAC && p.CrackedHMACSecret != "" {
		return []byte(p.CrackedHMACSecret)
	}
	return nil
}

func (p *ProbeCtx) Claims() (jwtlib.MapClaims, error) {
	te, err := editor.NewTokenEditor(p.TokenString)
	if err != nil {
		return nil, err
	}
	claims, ok := te.GetToken().Claims.(jwtlib.MapClaims)
	if !ok {
		return nil, errors.New("token claims are not a JSON object")
	}
	return claims, nil
}

func (p *ProbeCtx) MaxLifetime() time.Duration {
	if p.MaxTokenLifetime > 0 {
		return p.MaxTokenLifetime
	}
	return DefaultMaxTokenLifetime
}

const reasonNoSigningKey = "signing key unknown (pass a signing key or the HMAC secret, or let the secret check crack it)"

func SkipUnlessResignable() harnessx.SkipDecision {
	return harnessx.SkipWhen(func(_ context.Context, target harnessx.Target, _ harnessx.ResultStore) string {
		pctx := target.Data.(*ProbeCtx)
		if pctx.Offline {
			return "requires live server"
		}
		if pctx.ResigningKey() == nil {
			return reasonNoSigningKey
		}
		return ""
	})
}

func PresentClaims(claims jwtlib.MapClaims, candidates ...string) []string {
	var present []string
	for _, name := range candidates {
		if _, ok := claims[name]; ok {
			present = append(present, name)
		}
	}
	return present
}

func OtherClaimValue(v interface{}) interface{} {
	switch value := v.(type) {
	case string:
		return value + "-other"
	case []interface{}:
		if len(value) > 0 {
			if first, ok := value[0].(string); ok {
				return []string{first + "-other"}
			}
		}
	}
	return "other"
}

func NewOtherTokenCheck(def CheckDef, claim string, other func(pctx *ProbeCtx) string) harnessx.Check {
	skip := harnessx.SkipWhen(func(_ context.Context, target harnessx.Target, _ harnessx.ResultStore) string {
		pctx := target.Data.(*ProbeCtx)
		if pctx.Offline {
			return "requires live server"
		}
		if other(pctx) != "" {
			return ""
		}
		if pctx.ResigningKey() == nil {
			return "no token for another " + claim + " given and " + reasonNoSigningKey
		}
		claims, err := pctx.Claims()
		if err != nil {
			return err.Error()
		}
		if _, ok := claims[claim]; !ok {
			return "token has no " + claim + " claim and no token for another " + claim + " was given"
		}
		return ""
	})
	return NewTokenCheck(def, skip, func(pctx *ProbeCtx) (string, error) {
		if token := other(pctx); token != "" {
			return token, nil
		}
		claims, err := pctx.Claims()
		if err != nil {
			return "", err
		}
		return exploit.SetClaim(pctx.TokenString, pctx.ResigningKey(), claim, OtherClaimValue(claims[claim]))
	})
}
