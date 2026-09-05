package fuzz_test

import (
	"testing"

	"github.com/cerberauth/jwtop/jwt/fuzz"
	"github.com/stretchr/testify/assert"
)

func TestAllMutations_IncludesEveryCategory(t *testing.T) {
	mutations := fuzz.AllMutations(0)

	seen := map[fuzz.Category]bool{}
	for _, m := range mutations {
		seen[m.Category] = true
	}
	assert.True(t, seen[fuzz.CategoryTypeConfusion])
	assert.True(t, seen[fuzz.CategorySpecialChars])
	assert.True(t, seen[fuzz.CategoryOversizedString])
	assert.True(t, seen[fuzz.CategoryNullValue])
}

func TestOversizedStringMutation_DefaultsWhenNonPositive(t *testing.T) {
	m := fuzz.OversizedStringMutation(0)
	assert.Len(t, m.Value.(string), fuzz.DefaultMaxStringLen)
}

func TestOversizedStringMutation_UsesGivenLength(t *testing.T) {
	m := fuzz.OversizedStringMutation(42)
	assert.Len(t, m.Value.(string), 42)
}

func TestNullValueMutation_IsNil(t *testing.T) {
	m := fuzz.NullValueMutation()
	assert.Nil(t, m.Value)
}

func TestGenerateClaimMutations_OneEntryPerClaimTimesMutation(t *testing.T) {
	claims := map[string]any{"sub": "1234", "name": "John"}
	mutations := fuzz.GenerateClaimMutations(claims, 10)

	assert.Len(t, mutations, 2*len(fuzz.AllMutations(10)))
}

func TestGenerateClaimMutations_SkipsStandardTemporalClaims(t *testing.T) {
	claims := map[string]any{"sub": "1234", "exp": 1234567890, "iat": 1234567890, "nbf": 1234567890}
	mutations := fuzz.GenerateClaimMutations(claims, 10)

	for _, cm := range mutations {
		assert.NotContains(t, []string{"exp", "iat", "nbf"}, cm.Claim)
	}
}

func TestGenerateClaimMutations_DeterministicOrder(t *testing.T) {
	claims := map[string]any{"b": "1", "a": "2", "c": "3"}
	m1 := fuzz.GenerateClaimMutations(claims, 10)
	m2 := fuzz.GenerateClaimMutations(claims, 10)

	assert.Equal(t, m1, m2)
	assert.Equal(t, "a", m1[0].Claim)
}
