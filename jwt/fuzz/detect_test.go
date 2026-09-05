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
