package claimremoval

import (
	"context"
	_ "embed"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/harnessx/checkdef"
	"github.com/cerberauth/jwtop/jwt/crack/checkbase"
	"github.com/cerberauth/jwtop/jwt/exploit"
)

//go:embed check.yaml
var checkYAML []byte

var Def = checkdef.MustParseCheckDefYAML("claim_removal", checkYAML)

const VariantAll = "all"

var RegisteredClaims = []string{"iss", "aud", "sub", "exp", "nbf", "iat"}

var Check = checkdef.NewVariantCheck(Def,
	func(ctx context.Context, target harnessx.Target, variant string, store harnessx.ResultStore) (harnessx.Result, error) {
		pctx := target.Data.(*checkbase.ProbeCtx)
		claims, err := pctx.Claims()
		if err != nil {
			return checkbase.SendToken(ctx, target, store, "", err)
		}
		candidates := []string{variant}
		if variant == VariantAll {
			candidates = RegisteredClaims
		}
		removed := checkbase.PresentClaims(claims, candidates...)
		if len(removed) == 0 {
			return harnessx.Result{}, nil
		}
		token, err := exploit.RemoveClaims(pctx.TokenString, pctx.ResigningKey(), removed...)
		return checkbase.SendToken(ctx, target, store, token, err)
	},
	checkdef.WithVariants(append(append([]string{}, RegisteredClaims...), VariantAll)...),
	checkdef.WithSkip(checkbase.SkipUnlessResignable()),
)
