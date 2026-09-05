package fuzz

import (
	"regexp"
	"strings"
)

// stackTracePatterns match common unhandled-exception/stack-trace
// signatures across languages and frameworks, used to flag a fuzzed
// response as an error disclosure rather than a normal error response.
var stackTracePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)traceback \(most recent call last\)`),
	regexp.MustCompile(`(?is)panic:.*goroutine`),
	regexp.MustCompile(`(?i)exception in thread`),
	regexp.MustCompile(`(?i)at\s+java\.[\w.]+\(`),
	regexp.MustCompile(`(?i)nullpointerexception`),
	regexp.MustCompile(`(?i)system\.\w*exception`),
	regexp.MustCompile(`(?i)unhandled exception`),
	regexp.MustCompile(`(?i)fatal error:`),
	regexp.MustCompile(`(?i)whitelabel error page`),
	regexp.MustCompile(`(?i)org\.springframework\.[\w.]+`),
	regexp.MustCompile(`(?i)django\.core\.[\w.]+`),
	regexp.MustCompile(`(?i)ORA-\d{5}`),
	regexp.MustCompile(`(?i)sqlstate\[`),
	regexp.MustCompile(`(?i)stack trace:`),
	regexp.MustCompile(`(?i)<b>fatal error</b>`),
	regexp.MustCompile(`(?i)uncaught (type|reference)error`),
}

// ContainsStackTrace reports whether body looks like it leaked an unhandled
// exception or stack trace.
func ContainsStackTrace(body []byte) bool {
	for _, re := range stackTracePatterns {
		if re.Match(body) {
			return true
		}
	}
	return false
}

// DivergenceThreshold is the default fraction of the reference body length
// that a fuzzed response's body length must differ by to be flagged as a
// length-based divergence.
const DivergenceThreshold = 0.5

// Divergence describes why a fuzzed response was flagged as anomalous
// compared to the reference response captured from the original token.
type Divergence struct {
	ServerError bool // status >= 500
	StackTrace  bool // body matches a known stack-trace/exception signature
	LengthDiff  bool // body length differs from the reference by more than DivergenceThreshold
}

// Any reports whether any divergence signal fired.
func (d Divergence) Any() bool {
	return d.ServerError || d.StackTrace || d.LengthDiff
}

// String renders a short human-readable summary of which signals fired.
func (d Divergence) String() string {
	var reasons []string
	if d.ServerError {
		reasons = append(reasons, "5xx status")
	}
	if d.StackTrace {
		reasons = append(reasons, "stack trace")
	}
	if d.LengthDiff {
		reasons = append(reasons, "body length diverges")
	}
	return strings.Join(reasons, ", ")
}

// Detect compares a fuzzed response (status, body) against the reference
// response captured by sending the original, unmutated token (refLen <= 0
// disables the length-based signal, e.g. when the reference request
// itself failed).
func Detect(status int, body []byte, refLen int) Divergence {
	d := Divergence{
		ServerError: status >= 500,
		StackTrace:  ContainsStackTrace(body),
	}
	if refLen > 0 {
		diff := len(body) - refLen
		if diff < 0 {
			diff = -diff
		}
		d.LengthDiff = float64(diff) > float64(refLen)*DivergenceThreshold
	}
	return d
}
