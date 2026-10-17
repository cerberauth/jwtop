package fuzz_test

import (
	"strings"
	"testing"

	"github.com/cerberauth/jwtop/jwt/fuzz"
	"github.com/stretchr/testify/assert"
)

func TestContainsStackTrace_Positive(t *testing.T) {
	bodies := []string{
		"Traceback (most recent call last):\n  File \"app.py\"",
		"panic: runtime error\n\ngoroutine 1 [running]:",
		"java.lang.NullPointerException: null",
		"Whitelabel Error Page",
	}
	for _, b := range bodies {
		assert.True(t, fuzz.ContainsStackTrace([]byte(b)), b)
	}
}

func TestContainsStackTrace_Negative(t *testing.T) {
	assert.False(t, fuzz.ContainsStackTrace([]byte(`{"error":"unauthorized"}`)))
}

func TestDetect_ServerError(t *testing.T) {
	d := fuzz.Detect(500, []byte("ok"), 2)
	assert.True(t, d.ServerError)
	assert.True(t, d.Any())
}

func TestDetect_StackTrace(t *testing.T) {
	d := fuzz.Detect(200, []byte("panic: boom\n\ngoroutine 1 [running]:"), 2)
	assert.True(t, d.StackTrace)
	assert.True(t, d.Any())
}

func TestDetect_LengthDiff(t *testing.T) {
	ref := 10
	d := fuzz.Detect(200, []byte(strings.Repeat("a", 100)), ref)
	assert.True(t, d.LengthDiff)
	assert.True(t, d.Any())
}

func TestDetectReflecting_DifferentStatusIgnoresLengthDiff(t *testing.T) {
	for _, status := range []int{204, 302, 400, 401, 404} {
		d := fuzz.DetectReflecting(status, nil, 200, 36, nil)
		assert.False(t, d.Any(), status)
	}
}

func TestDetectReflecting_SameStatusFlagsLengthDiff(t *testing.T) {
	d := fuzz.DetectReflecting(400, []byte(strings.Repeat("a", 500)), 400, 36, nil)
	assert.True(t, d.LengthDiff)
}

func TestDetectReflecting_DifferentStatusStillFlagsStackTraceAnd5xx(t *testing.T) {
	d := fuzz.DetectReflecting(400, []byte("panic: boom\n\ngoroutine 1 [running]:"), 200, 36, nil)
	assert.True(t, d.StackTrace)
	assert.True(t, fuzz.DetectReflecting(500, nil, 200, 36, nil).ServerError)
}

func TestDetectReflecting_IgnoresEchoedPayload(t *testing.T) {
	payload := strings.Repeat("A", 10000)
	body := []byte(`{"coupon":"` + payload + `"}`)
	assert.True(t, fuzz.Detect(200, body, 20).LengthDiff)
	assert.False(t, fuzz.DetectReflecting(200, body, 200, 20, payload).Any())
}

func TestDetectReflecting_JSONEscapedPayload(t *testing.T) {
	payload := "<script>alert(1)</script>\r\nX: y"
	body := []byte(`{"filter":"\u003cscript\u003ealert(1)\u003c/script\u003e\r\nX: y","matches":0}`)
	assert.False(t, fuzz.DetectReflecting(200, body, 200, 27, payload).LengthDiff)
}

func TestDetectReflecting_ASCIIEscapedPayload(t *testing.T) {
	payload := "\u202eevil\u202c"
	body := []byte(`{"filter":"\u202eevil\u202c","matches":0}`)
	assert.False(t, fuzz.DetectReflecting(200, body, 200, 20, payload).LengthDiff)
}

func TestDetectReflecting_StillFlagsUnrelatedGrowth(t *testing.T) {
	body := []byte(strings.Repeat("x", 500))
	assert.True(t, fuzz.DetectReflecting(200, body, 200, 20, "AAAA").LengthDiff)
}

func TestDetectReflecting_StillFlagsStackTraceWhenReflected(t *testing.T) {
	d := fuzz.DetectReflecting(500, []byte("panic: AAAA\n\ngoroutine 1 [running]:"), 200, 20, "AAAA")
	assert.True(t, d.ServerError)
	assert.True(t, d.StackTrace)
}

func TestDetect_NoDivergence(t *testing.T) {
	ref := 10
	d := fuzz.Detect(200, []byte(strings.Repeat("a", 12)), ref)
	assert.False(t, d.Any())
}

func TestDetect_RefLenZeroDisablesLengthSignal(t *testing.T) {
	d := fuzz.Detect(200, []byte(strings.Repeat("a", 10000)), 0)
	assert.False(t, d.LengthDiff)
}

func TestDivergence_String(t *testing.T) {
	d := fuzz.Divergence{ServerError: true, StackTrace: true}
	assert.Equal(t, "5xx status, stack trace", d.String())
}
