package kidpathtraversal

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

var Def = checkdef.MustParseCheckDefYAML("kid_path_traversal", checkYAML)

// variantIndex maps a variant string (an entry of
// exploit.KidPathTraversalVariants) to its position, so a caller-supplied
// single KidPath override (see below) can run on only one variant slot.
var variantIndex = func() map[string]int {
	m := make(map[string]int, len(exploit.KidPathTraversalVariants))
	for i, v := range exploit.KidPathTraversalVariants {
		m[v] = i
	}
	return m
}()

var Check = checkdef.NewVariantCheck(Def,
	func(ctx context.Context, target harnessx.Target, variant string, store harnessx.ResultStore) (harnessx.Result, error) {
		pctx := target.Data.(*checkbase.ProbeCtx)
		if pctx.Offline {
			return harnessx.Result{}, nil
		}

		path := variant
		if pctx.KidPath != "" {
			// A caller-supplied single path overrides the default variant
			// list — only the first variant slot runs, carrying the
			// custom path, so the same override isn't probed repeatedly.
			if variantIndex[variant] != 0 {
				return harnessx.Result{}, nil
			}
			path = pctx.KidPath
		}

		token, err := exploit.KidPathTraversal(pctx.TokenString, path, []byte(""))
		return checkbase.SendToken(ctx, target, store, token, err)
	},
	checkdef.WithVariants(exploit.KidPathTraversalVariants...),
	checkdef.WithSkip(harnessx.SkipWhen(func(_ context.Context, target harnessx.Target, store harnessx.ResultStore) string {
		if target.Data.(*checkbase.ProbeCtx).Offline {
			return "requires live server (server-side key lookup)"
		}
		if pr, ok := harnessx.GetData[checkbase.ProbeResult](store, "blanksecret"); ok && pr.Vulnerable {
			return "server accepts a blank HMAC secret regardless of kid — see Blank Secret finding"
		}
		return ""
	})),
)
