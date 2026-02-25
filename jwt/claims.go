package jwt

import (
	"encoding/json"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/iancoleman/orderedmap"
)

// OrderedMapClaims wraps jwt.Claims and preserves the original claim order when
// marshaling. This ensures that re-signed tokens maintain the same claim
// ordering as the source token.
type OrderedMapClaims struct {
	jwt.Claims
	Raw string // Original token string used to recover claim insertion order.
}

// NewOrderedMapClaims creates an OrderedMapClaims from a parsed token.
func NewOrderedMapClaims(token *jwt.Token) *OrderedMapClaims {
	return &OrderedMapClaims{Claims: token.Claims, Raw: token.Raw}
}

// MarshalJSON serializes claims in the original key order.
func (m OrderedMapClaims) MarshalJSON() ([]byte, error) {
	parts := strings.Split(m.Raw, ".")
	if len(parts) != 3 {
		return nil, jwt.ErrTokenMalformed
	}

	p := jwt.NewParser()
	claimBytes, err := p.DecodeSegment(parts[1])
	if err != nil {
		return nil, jwt.ErrTokenMalformed
	}

	o := orderedmap.New()
	if err := json.Unmarshal(claimBytes, o); err != nil {
		return nil, err
	}

	if mapClaims, ok := m.Claims.(jwt.MapClaims); ok {
		for k, v := range mapClaims {
			o.Set(k, v)
		}
	}

	return json.Marshal(o)
}
