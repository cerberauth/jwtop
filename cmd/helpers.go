package cmd

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/cerberauth/jwtop/jwt"
	"github.com/cerberauth/x/fsx"
	jwtlib "github.com/golang-jwt/jwt/v5"
)

func isURL(s string) bool {
	return strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://")
}

func readKeyData(keyFileOrURL string) ([]byte, error) {
	if isURL(keyFileOrURL) {
		//nolint:gosec
		resp, err := http.Get(keyFileOrURL)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("fetching key: HTTP %d", resp.StatusCode)
		}
		return io.ReadAll(resp.Body)
	}
	return fsx.ReadFile(keyFileOrURL)
}

func resolveKey(secret, keyFile string, publicKey bool) (interface{}, []byte, error) {
	if secret != "" && keyFile != "" {
		return nil, nil, errors.New("specify either --secret or --key, not both")
	}

	if secret != "" {
		return []byte(secret), []byte(secret), nil
	}

	if keyFile != "" {
		pemData, err := readKeyData(keyFile)
		if err != nil {
			return nil, nil, err
		}

		var key interface{}
		if publicKey {
			key, err = jwt.LoadPublicKeyFromPEM(pemData)
			if err != nil {
				key, err = jwt.LoadPrivateKeyFromPEM(pemData)
				if err != nil {
					return nil, nil, err
				}
			}
		} else {
			key, err = jwt.LoadPrivateKeyFromPEM(pemData)
			if err != nil {
				return nil, nil, err
			}
		}

		return key, pemData, nil
	}

	return nil, nil, errors.New("no key provided: use --secret or --key")
}

// ParseSigningMethod returns the jwt.SigningMethod for the given algorithm name.
func ParseSigningMethod(alg string) (jwtlib.SigningMethod, error) {
	return jwt.ParseSigningMethod(alg)
}

// readTokenArg returns the JWT token string. When args contains at least one
// element its first element is returned directly. Otherwise the entire content
// of stdin is read, trimmed, and returned — allowing any token-accepting
// command to be used in a pipeline:
//
//	jwtop find --file page.html | jwtop decode
func readTokenArg(args []string) (string, error) {
	if len(args) > 0 {
		return args[0], nil
	}
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		return "", fmt.Errorf("reading stdin: %w", err)
	}
	token := strings.TrimSpace(string(data))
	if token == "" {
		return "", errors.New("no token provided: pass a token as an argument or via stdin")
	}
	return token, nil
}
