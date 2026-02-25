package editor

import (
	"encoding/base64"
	"encoding/json"
	"strings"

	jwtpkg "github.com/cerberauth/jwtop/jwt"
)

// WithoutSignature produces a token with the original header and payload but
// an empty signature segment (i.e. "header.payload."). Unlike WithAlgNone, the
// header alg field is preserved, so the token's declared algorithm does not change.
// This works for all signing methods, not just HMAC.
func (j *TokenEditor) WithoutSignature() (string, error) {
	claimsJSON, err := json.Marshal(jwtpkg.NewOrderedMapClaims(j.GetToken()))
	if err != nil {
		return "", err
	}
	parts := strings.SplitN(j.GetToken().Raw, ".", 3)
	return parts[0] + "." + base64.RawURLEncoding.EncodeToString(claimsJSON) + ".", nil
}
