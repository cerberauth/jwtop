package cmd

import (
	"context"
	"errors"
	"io"
	"os"
	"testing"
	"time"

	"github.com/cerberauth/jwtop/jwt/crack/checkbase"
	"github.com/cerberauth/jwtop/jwt/exploit/external"
	"github.com/cerberauth/x/telemetryx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
)

func TestExternalToolFlags_UseJohn(t *testing.T) {
	assert.False(t, externalToolFlags{}.useJohn())
	assert.True(t, externalToolFlags{John: true}.useJohn())
	assert.True(t, externalToolFlags{JohnPath: "/usr/bin/john"}.useJohn(), "an explicit path implies enablement without needing the bool flag too")
}

func TestExternalToolFlags_UseHashcat(t *testing.T) {
	assert.False(t, externalToolFlags{}.useHashcat())
	assert.True(t, externalToolFlags{Hashcat: true}.useHashcat())
	assert.True(t, externalToolFlags{HashcatPath: "/usr/bin/hashcat"}.useHashcat(), "an explicit path implies enablement without needing the bool flag too")
}

func TestExternalToolFlags_ToOptions(t *testing.T) {
	f := externalToolFlags{JohnPath: "/x/john", Hashcat: true, Timeout: 2 * time.Minute}
	opts := f.toOptions()
	assert.True(t, opts.UseJohn)
	assert.Equal(t, "/x/john", opts.JohnPath)
	assert.True(t, opts.UseHashcat)
	assert.Equal(t, 2*time.Minute, opts.Timeout)
}

func withCapturedStderr(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stderr
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stderr = w
	defer func() { os.Stderr = orig }()

	fn()

	require.NoError(t, w.Close())
	out, err := io.ReadAll(r)
	require.NoError(t, err)
	return string(out)
}

func TestReportExternalToolAvailability_AdvisesWhenNotEnabled(t *testing.T) {
	origDetect := detectExternalTools
	defer func() { detectExternalTools = origDetect }()
	detectExternalTools = func() external.Availability {
		return external.Availability{
			John:    external.ToolStatus{Name: "john", Installed: true},
			Hashcat: external.ToolStatus{Name: "hashcat", Installed: true},
		}
	}

	counter, _ := telemetryx.GetMeterProvider().Meter("test").Int64Counter("test.detected")

	out := withCapturedStderr(t, func() {
		reportExternalToolAvailability(context.Background(), counter, externalToolFlags{})
	})

	assert.Contains(t, out, "john detected on PATH")
	assert.Contains(t, out, "hashcat detected on PATH")
}

func TestReportExternalToolAvailability_SilentWhenEnabled(t *testing.T) {
	origDetect := detectExternalTools
	defer func() { detectExternalTools = origDetect }()
	detectExternalTools = func() external.Availability {
		return external.Availability{
			John:    external.ToolStatus{Name: "john", Installed: true},
			Hashcat: external.ToolStatus{Name: "hashcat", Installed: true},
		}
	}

	counter, _ := telemetryx.GetMeterProvider().Meter("test").Int64Counter("test.detected")

	out := withCapturedStderr(t, func() {
		reportExternalToolAvailability(context.Background(), counter, externalToolFlags{John: true, Hashcat: true})
	})

	assert.Empty(t, out)
}

func TestReportExternalToolAvailability_SilentWhenNotInstalled(t *testing.T) {
	origDetect := detectExternalTools
	defer func() { detectExternalTools = origDetect }()
	detectExternalTools = func() external.Availability { return external.Availability{} }

	counter, _ := telemetryx.GetMeterProvider().Meter("test").Int64Counter("test.detected")

	out := withCapturedStderr(t, func() {
		reportExternalToolAvailability(context.Background(), counter, externalToolFlags{})
	})

	assert.Empty(t, out)
}

func TestExternalToolErrorReason(t *testing.T) {
	assert.Equal(t, "", externalToolErrorReason(nil))
	assert.Equal(t, "not_installed", externalToolErrorReason(external.ErrNotInstalled))
	assert.Equal(t, "timeout", externalToolErrorReason(external.ErrTimedOut))
	assert.Equal(t, "invocation_failed", externalToolErrorReason(errors.New("boom")))
}

func TestRecordExternalToolEvents_WarnsOnTimeout(t *testing.T) {
	counters := buildToolOutcomeCounters(telemetryx.GetMeterProvider().Meter("test"), "test.weaksecret")
	tracer := otel.Tracer("test")

	events := []checkbase.ExternalToolEvent{
		{Tool: "john", Outcome: "timeout", Err: external.ErrTimedOut, TimedOut: true, Duration: 5 * time.Minute},
	}

	out := withCapturedStderr(t, func() {
		recordExternalToolEvents(context.Background(), tracer, counters, "test.weaksecret", events)
	})

	assert.Contains(t, out, "john timed out after")
}

func TestRecordExternalToolEvents_SilentOnSuccess(t *testing.T) {
	counters := buildToolOutcomeCounters(telemetryx.GetMeterProvider().Meter("test"), "test.weaksecret")
	tracer := otel.Tracer("test")

	events := []checkbase.ExternalToolEvent{
		{Tool: "hashcat", Outcome: "success", Duration: time.Second},
	}

	out := withCapturedStderr(t, func() {
		recordExternalToolEvents(context.Background(), tracer, counters, "test.weaksecret", events)
	})

	assert.Empty(t, out)
}

func TestRecordExternalToolEvents_EmptyIsNoop(t *testing.T) {
	counters := buildToolOutcomeCounters(telemetryx.GetMeterProvider().Meter("test"), "test.weaksecret")
	tracer := otel.Tracer("test")

	out := withCapturedStderr(t, func() {
		recordExternalToolEvents(context.Background(), tracer, counters, "test.weaksecret", nil)
	})
	assert.Empty(t, out)
}
