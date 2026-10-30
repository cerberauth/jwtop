package fuzz

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf16"
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
	return detect(status, body, refLen, true, nil)
}

// DetectReflecting is Detect for a response to a token whose claim was
// replaced by payload, with the reference response's status known.
//
// The length-based signal only applies when status equals refStatus: a
// response with a different status (a 4xx rejection, a redirect, ...) is a
// different kind of response, so its body size says nothing about a parsing
// bug. 5xx statuses and stack traces are flagged regardless. When payload is
// a string that the server echoes back verbatim or JSON-escaped, the echoed
// copies are excluded from the body length, since a response that merely
// grows with the input it reflects is not diverging.
func DetectReflecting(status int, body []byte, refStatus, refLen int, payload any) Divergence {
	return detect(status, body, refLen, status == refStatus, payload)
}

func detect(status int, body []byte, refLen int, compareLen bool, payload any) Divergence {
	d := Divergence{
		ServerError: status >= 500,
		StackTrace:  ContainsStackTrace(body),
	}
	if refLen > 0 && compareLen {
		diff := len(stripReflected(body, payload)) - refLen
		if diff < 0 {
			diff = -diff
		}
		d.LengthDiff = float64(diff) > float64(refLen)*DivergenceThreshold
	}
	return d
}

// stripReflected removes every copy of payload (raw, or JSON-escaped with and
// without HTML escaping) from body. Non-string and empty payloads are left
// alone.
func stripReflected(body []byte, payload any) []byte {
	str, ok := payload.(string)
	if !ok || str == "" {
		return body
	}
	forms := [][]byte{[]byte(str)}
	if b, err := json.Marshal(str); err == nil && len(b) > 2 {
		forms = append(forms, b[1:len(b)-1])
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(str); err == nil {
		if b := bytes.TrimSuffix(buf.Bytes(), []byte("\n")); len(b) > 2 {
			forms = append(forms, append([]byte(nil), b[1:len(b)-1]...))
		}
	}
	forms = append(forms, []byte(escapeNonASCII(str)))
	for _, f := range forms {
		body = bytes.ReplaceAll(body, f, nil)
	}
	return body
}

// escapeNonASCII renders str the way JSON encoders that escape every
// non-ASCII character do (e.g. "\u202e"), as a JSON string body without the
// surrounding quotes.
func escapeNonASCII(str string) string {
	var sb strings.Builder
	for _, r := range str {
		switch {
		case r == '"' || r == '\\':
			sb.WriteByte('\\')
			sb.WriteRune(r)
		case r == '\n':
			sb.WriteString(`\n`)
		case r == '\r':
			sb.WriteString(`\r`)
		case r == '\t':
			sb.WriteString(`\t`)
		case r < 0x20 || r > 0x7e:
			for _, u := range utf16.Encode([]rune{r}) {
				fmt.Fprintf(&sb, `\u%04x`, u)
			}
		default:
			sb.WriteRune(r)
		}
	}
	return sb.String()
}
