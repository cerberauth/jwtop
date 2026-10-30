package checkbase

import (
	"strings"

	"github.com/cerberauth/harnessx"
)

// ResolveVariantResult reduces the per-variant Attempts of a
// checkdef.NewVariantCheck result down to the single ProbeResult a report
// line needs: the first attempt whose ProbeResult is Vulnerable (in
// declared variant order), or — if none matched — the last attempt tried,
// annotated with every variant name that was attempted. ok is false when no
// attempt carried a ProbeResult (e.g. every variant was skipped offline).
func ResolveVariantResult(attempts []harnessx.Attempt) (pr ProbeResult, ok bool) {
	tried := make([]string, 0, len(attempts))
	for _, a := range attempts {
		attemptResult, isProbeResult := a.Data.(ProbeResult)
		if !isProbeResult {
			continue
		}
		ok = true
		tried = append(tried, a.Variant)
		if attemptResult.Vulnerable {
			if attemptResult.Extra == "" {
				attemptResult.Extra = "variant: " + a.Variant
			}
			return attemptResult, true
		}
		pr = attemptResult
	}
	if ok {
		pr.Extra = "tried: " + strings.Join(tried, ", ")
	}
	return pr, ok
}
