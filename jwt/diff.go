package jwt

import (
	"encoding/json"
	"reflect"
	"sort"
)

// FieldChange describes how a single header or claim key differs between the
// base token and a compared token.
type FieldChange struct {
	Key    string      `json:"key"`             // Header or claim name.
	Status string      `json:"status"`          // One of "added", "removed", "changed".
	Base   interface{} `json:"base,omitempty"`  // Value on the base token; absent when Status is "added".
	Other  interface{} `json:"other,omitempty"` // Value on the compared token; absent when Status is "removed".
}

// TokenDiff holds the differences between the base token and one other token.
type TokenDiff struct {
	Token            string        `json:"token"`            // The compared token, as passed in.
	Header           []FieldChange `json:"header"`           // Header (JOSE) differences, sorted by key.
	Claims           []FieldChange `json:"claims"`           // Claims (payload) differences, sorted by key.
	SignatureChanged bool          `json:"signatureChanged"` // Whether the raw signature segment differs from the base.
	IdenticalToBase  bool          `json:"identical"`        // True when header, claims, and signature all match the base.
}

// DiffResult is the outcome of comparing a base token against one or more
// other tokens.
type DiffResult struct {
	Base  string      `json:"base"`
	Diffs []TokenDiff `json:"diffs"`
}

// Diff decodes base and each of others, then reports, for each of others,
// which header/claims keys were added, removed, or changed relative to base,
// plus whether the signature differs. It returns an error if any token fails
// to decode.
func Diff(base string, others ...string) (*DiffResult, error) {
	baseDecoded, err := Decode(base)
	if err != nil {
		return nil, err
	}

	result := &DiffResult{Base: base}
	for _, other := range others {
		otherDecoded, err := Decode(other)
		if err != nil {
			return nil, err
		}

		headerChanges := diffFields(baseDecoded.Header, otherDecoded.Header)
		claimsChanges := diffFields(baseDecoded.Claims, otherDecoded.Claims)
		signatureChanged := baseDecoded.Signature != otherDecoded.Signature

		result.Diffs = append(result.Diffs, TokenDiff{
			Token:            other,
			Header:           headerChanges,
			Claims:           claimsChanges,
			SignatureChanged: signatureChanged,
			IdenticalToBase:  len(headerChanges) == 0 && len(claimsChanges) == 0 && !signatureChanged,
		})
	}

	return result, nil
}

// diffFields compares two decoded header/claims maps and returns the sorted
// set of keys whose presence or value differs.
func diffFields(base, other map[string]interface{}) []FieldChange {
	keys := make(map[string]struct{}, len(base)+len(other))
	for k := range base {
		keys[k] = struct{}{}
	}
	for k := range other {
		keys[k] = struct{}{}
	}

	changes := []FieldChange{}
	for k := range keys {
		baseVal, inBase := base[k]
		otherVal, inOther := other[k]

		switch {
		case !inBase:
			changes = append(changes, FieldChange{Key: k, Status: "added", Other: otherVal})
		case !inOther:
			changes = append(changes, FieldChange{Key: k, Status: "removed", Base: baseVal})
		case !valuesEqual(baseVal, otherVal):
			changes = append(changes, FieldChange{Key: k, Status: "changed", Base: baseVal, Other: otherVal})
		}
	}

	sort.Slice(changes, func(i, j int) bool { return changes[i].Key < changes[j].Key })
	return changes
}

// valuesEqual compares two decoded JSON values for equality. It normalises
// through JSON marshalling first so that equivalent numeric representations
// (e.g. float64(1) vs json.Number "1") don't register as spurious changes.
func valuesEqual(a, b interface{}) bool {
	if reflect.DeepEqual(a, b) {
		return true
	}
	aJSON, aErr := json.Marshal(a)
	bJSON, bErr := json.Marshal(b)
	if aErr != nil || bErr != nil {
		return false
	}
	return string(aJSON) == string(bJSON)
}
