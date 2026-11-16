package audiencenotvalidated

import (
	_ "embed"

	"github.com/cerberauth/harnessx/checkdef"
	"github.com/cerberauth/jwtop/jwt/crack/checkbase"
)

//go:embed check.yaml
var checkYAML []byte

var Def = checkdef.MustParseCheckDefYAML("audience_not_validated", checkYAML)

var Check = checkbase.NewOtherTokenCheck(Def, "aud", func(pctx *checkbase.ProbeCtx) string {
	return pctx.OtherAudienceToken
})
