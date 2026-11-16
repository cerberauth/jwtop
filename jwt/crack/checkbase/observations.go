package checkbase

import (
	"context"
	"strconv"

	"github.com/cerberauth/harnessx"
)

// WithObservations returns c reporting a vulnerable ProbeResult as an
// Observation, as the check pack contract requires. Result.Data keeps the
// ProbeResult for dependent checks.
func WithObservations(c harnessx.Check) harnessx.Check {
	if c.Run != nil {
		run := c.Run
		c.Run = func(ctx context.Context, target harnessx.Target, store harnessx.ResultStore) (harnessx.Result, error) {
			r, err := run(ctx, target, store)
			return observe(c, r), err
		}
	}
	if c.RunVariant != nil {
		run := c.RunVariant
		c.RunVariant = func(ctx context.Context, target harnessx.Target, variant string, store harnessx.ResultStore) (harnessx.Result, error) {
			r, err := run(ctx, target, variant, store)
			return observe(c, r), err
		}
	}
	return c
}

func observe(c harnessx.Check, r harnessx.Result) harnessx.Result {
	pr, ok := harnessx.DataAs[ProbeResult](r)
	if !ok || !pr.Vulnerable {
		return r
	}
	title := pr.Name
	if title == "" {
		title = c.Name
	}
	obs := harnessx.Observation{
		Title:       title,
		Description: c.Description,
		Evidence:    pr.Payload,
	}
	if pr.Status != 0 || pr.Extra != "" {
		obs.Metadata = map[string]string{}
		if pr.Status != 0 {
			obs.Metadata["status"] = strconv.Itoa(pr.Status)
		}
		if pr.Extra != "" {
			obs.Metadata["extra"] = pr.Extra
		}
	}
	r.Observations = append(append([]harnessx.Observation(nil), r.Observations...), obs)
	return r
}
