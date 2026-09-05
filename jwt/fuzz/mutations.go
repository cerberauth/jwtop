package fuzz

import (
	"fmt"
	"sort"
	"strings"
)

// Category identifies the kind of mutation applied to a claim value.
type Category string

const (
	CategoryTypeConfusion   Category = "type_confusion"
	CategoryOversizedString Category = "oversized_string"
	CategorySpecialChars    Category = "special_chars"
	CategoryNullValue       Category = "null_value"
)

// Mutation is one candidate replacement value for a claim, tagged with the
// category it belongs to and a short human-readable name for reporting.
type Mutation struct {
	Category Category
	Name     string
	Value    any
}

// DefaultMaxStringLen is the length of the oversized-string mutation
// payload used when no override is supplied.
const DefaultMaxStringLen = 10_000

// standardClaims are skipped by GenerateClaimMutations: mutating their type
// mostly just makes the token fail temporal/parsing validation before it
// reaches application logic, which is not what this mode is probing for.
var standardClaims = map[string]bool{
	"exp": true,
	"nbf": true,
	"iat": true,
}

// TypeConfusionMutations returns payloads that each replace a claim's usual
// scalar value with a different JSON type (number, float, boolean, array,
// object).
func TypeConfusionMutations() []Mutation {
	return []Mutation{
		{CategoryTypeConfusion, "integer", 1337},
		{CategoryTypeConfusion, "float", 13.37},
		{CategoryTypeConfusion, "boolean", true},
		{CategoryTypeConfusion, "array", []any{"a", "b", "c"}},
		{CategoryTypeConfusion, "object", map[string]any{"a": "b"}},
	}
}

// SpecialCharsMutations returns payloads exercising common injection and
// encoding edge cases: SQL/command/template injection, XSS, path
// traversal, null bytes, format strings, CRLF injection, and Unicode
// direction overrides.
func SpecialCharsMutations() []Mutation {
	return []Mutation{
		{CategorySpecialChars, "sql_injection", "' OR '1'='1"},
		{CategorySpecialChars, "xss", "<script>alert(1)</script>"},
		{CategorySpecialChars, "path_traversal", "../../../../etc/passwd"},
		{CategorySpecialChars, "null_byte", "value\x00.txt"},
		{CategorySpecialChars, "format_string", "%s%s%s%s%n"},
		{CategorySpecialChars, "template_injection", "${7*7}{{7*7}}"},
		{CategorySpecialChars, "crlf_injection", "value\r\nSet-Cookie: pwned=true"},
		{CategorySpecialChars, "unicode_override", "\u202eevil\u202c"},
		{CategorySpecialChars, "command_injection", "; cat /etc/passwd"},
	}
}

// OversizedStringMutation returns a single mutation whose value is a string
// of maxLen characters (DefaultMaxStringLen when maxLen <= 0), to probe for
// buffer/allocation issues on unexpectedly large claim values.
func OversizedStringMutation(maxLen int) Mutation {
	if maxLen <= 0 {
		maxLen = DefaultMaxStringLen
	}
	return Mutation{CategoryOversizedString, fmt.Sprintf("oversized_%d", maxLen), strings.Repeat("A", maxLen)}
}

// NullValueMutation returns the mutation that replaces a claim's value with
// a literal JSON null.
func NullValueMutation() Mutation {
	return Mutation{CategoryNullValue, "null", nil}
}

// AllMutations returns the full default mutation catalog applied to every
// claim by GenerateClaimMutations: type confusion, special characters, one
// oversized string, and an explicit null.
func AllMutations(maxStringLen int) []Mutation {
	m := TypeConfusionMutations()
	m = append(m, SpecialCharsMutations()...)
	m = append(m, OversizedStringMutation(maxStringLen), NullValueMutation())
	return m
}

// ClaimMutation is one (claim, mutation) pair to try against the target:
// the claim named Claim gets its value replaced with Mutation.Value.
type ClaimMutation struct {
	Claim    string
	Mutation Mutation
}

// GenerateClaimMutations returns one ClaimMutation per (claim, mutation)
// combination in claims × AllMutations(maxStringLen), in a deterministic
// (sorted by claim name) order. Registered temporal claims (exp/nbf/iat)
// are skipped — see standardClaims.
func GenerateClaimMutations(claims map[string]any, maxStringLen int) []ClaimMutation {
	keys := make([]string, 0, len(claims))
	for k := range claims {
		if standardClaims[k] {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)

	mutations := AllMutations(maxStringLen)
	out := make([]ClaimMutation, 0, len(keys)*len(mutations))
	for _, k := range keys {
		for _, m := range mutations {
			out = append(out, ClaimMutation{Claim: k, Mutation: m})
		}
	}
	return out
}
