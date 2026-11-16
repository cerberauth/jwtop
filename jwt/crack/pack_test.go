package crack_test

import (
	"context"
	"regexp"
	"testing"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/harnessx/embed"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cerberauth/jwtop/jwt/crack"
)

var packID = regexp.MustCompile(`^jwt\.[a-z0-9]+(_[a-z0-9]+)*$`)

func TestChecks_FollowPackContract(t *testing.T) {
	checks := crack.Checks()
	require.NotEmpty(t, checks)
	ids := map[harnessx.CheckID]bool{}
	for _, c := range checks {
		assert.Regexp(t, packID, string(c.ID))
		ids[c.ID] = true
		assert.Equal(t, c.ID == crack.BaselineCheckID, c.Internal, "only the baseline is internal: %s", c.ID)
	}
	for _, c := range checks {
		for _, dep := range c.DependsOn {
			assert.True(t, ids[dep], "%s depends on unknown %s", c.ID, dep)
		}
	}
	require.NoError(t, harnessx.New().Register(checks...))

	legacy, _ := crack.BuildChecks()
	for _, c := range legacy {
		assert.False(t, c.Internal, "%s", c.ID)
	}
}

func TestChecks_ReportVulnerableProbesAsObservations(t *testing.T) {
	srv := staticServer(200)
	defer srv.Close()
	token := makeHS256Token(t, "secret")

	pctx, err := crack.NewProbeCtx(token, crack.ProbeOptions{URL: srv.URL})
	require.NoError(t, err)

	summary, err := harnessx.New(harnessx.WithChecks(crack.Checks()...)).Run(context.Background(), harnessx.Target{URL: srv.URL, Data: pctx})
	require.NoError(t, err)

	byCheck := map[harnessx.CheckID]int{}
	for _, o := range summary.Observations {
		byCheck[o.CheckID]++
	}
	assert.Equal(t, 1, byCheck["jwt.no_verification"])
	for _, r := range summary.Results {
		assert.NotEqual(t, crack.BaselineCheckID, r.CheckID)
	}
}

func TestChecks_EmbedPerResource(t *testing.T) {
	srv := staticServer(200)
	defer srv.Close()
	token := makeHS256Token(t, "secret")

	discover := harnessx.Check{ID: "api.discover", Run: func(context.Context, harnessx.Target, harnessx.ResultStore) (harnessx.Result, error) {
		return harnessx.Result{Resources: []harnessx.Resource{{ID: "a", URL: srv.URL + "/a"}, {ID: "b", URL: srv.URL + "/b"}}}, nil
	}}
	checks, err := embed.Checks(crack.Checks(), embed.Options{
		Scope:     harnessx.ScopePerResource,
		DependsOn: []harnessx.CheckID{discover.ID},
		Context: func(_ context.Context, _ harnessx.Target, res *harnessx.Resource) (any, error) {
			return crack.NewProbeCtx(token, crack.ProbeOptions{URL: res.URL})
		},
	})
	require.NoError(t, err)

	summary, err := harnessx.New(harnessx.WithChecks(append([]harnessx.Check{discover}, checks...)...)).Run(context.Background(), harnessx.Target{URL: srv.URL})
	require.NoError(t, err)

	for _, r := range summary.Results {
		assert.NoError(t, r.Err, "%s/%s", r.CheckID, r.ResourceID)
	}
	vulnerable := map[string]bool{}
	for _, o := range summary.Observations {
		if o.CheckID == "jwt.no_verification" {
			vulnerable[o.ResourceID] = true
		}
	}
	assert.Equal(t, map[string]bool{"a": true, "b": true}, vulnerable)
}
