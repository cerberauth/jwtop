package jwt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
)

// Key-generation security defaults and lower bounds.
const (
	// MinRSABits is the smallest RSA modulus size allowed. 2048 bits is the
	// floor recommended by NIST SP 800-57 and RFC 7518 for RS*/PS* algorithms.
	MinRSABits = 2048
	// DefaultRSABits is used when the caller does not pick an RSA key size.
	DefaultRSABits = 2048
)

// SecretFormat controls how a generated HMAC secret is encoded for output.
type SecretFormat string

const (
	SecretFormatBase64URL SecretFormat = "base64url" // unpadded, URL-safe (default)
	SecretFormatBase64    SecretFormat = "base64"    // standard, padded
	SecretFormatHex       SecretFormat = "hex"
	SecretFormatRaw       SecretFormat = "raw" // raw bytes, no encoding
)

// GenerateKeyOptions holds the user-chosen parameters for key generation.
type GenerateKeyOptions struct {
	// Algorithm is the JWA name the key is generated for: HS256/384/512,
	// RS256/384/512, PS256/384/512, ES256/384/512 or EdDSA.
	Algorithm string
	// RSABits selects the RSA modulus size. Ignored for non-RSA algorithms.
	// Zero means DefaultRSABits. Values below MinRSABits are rejected.
	RSABits int
	// SecretBytes selects the HMAC secret length in bytes. Ignored for
	// asymmetric algorithms. Zero means "match the HMAC output size"
	// (32/48/64 for HS256/384/512). Shorter values are rejected because a
	// secret weaker than the MAC output size reduces the security margin.
	SecretBytes int
}

// GeneratedKey is the result of GenerateKeyPair.
type GeneratedKey struct {
	Algorithm string

	// Asymmetric algorithms populate these. PrivateKey is the crypto key
	// value; PrivatePEM/PublicPEM are PKCS#8 / PKIX PEM encodings.
	PrivateKey any
	PublicKey  any
	PrivatePEM []byte
	PublicPEM  []byte

	// HMAC algorithms populate this with the raw random secret.
	Secret []byte
}

// EncodeSecret renders the generated HMAC secret in the requested format.
func (g *GeneratedKey) EncodeSecret(format SecretFormat) (string, error) {
	if g.Secret == nil {
		return "", errors.New("no HMAC secret on this key")
	}
	switch format {
	case SecretFormatBase64URL, "":
		return base64.RawURLEncoding.EncodeToString(g.Secret), nil
	case SecretFormatBase64:
		return base64.StdEncoding.EncodeToString(g.Secret), nil
	case SecretFormatHex:
		return hex.EncodeToString(g.Secret), nil
	case SecretFormatRaw:
		return string(g.Secret), nil
	default:
		return "", fmt.Errorf("unknown secret format %q", format)
	}
}

func hmacSecretMinBytes(alg string) int {
	switch alg {
	case "HS256":
		return 32
	case "HS384":
		return 48
	case "HS512":
		return 64
	}
	return 32
}

// GenerateKeyPair creates fresh key material for the given algorithm using the
// crypto/rand CSPRNG, enforcing minimum-strength parameters while letting the
// caller pick sizes above the floor.
func GenerateKeyPair(opts GenerateKeyOptions) (*GeneratedKey, error) {
	alg := strings.ToUpper(strings.TrimSpace(opts.Algorithm))

	switch alg {
	case "HS256", "HS384", "HS512":
		return generateHMAC(alg, opts.SecretBytes)

	case "RS256", "RS384", "RS512", "PS256", "PS384", "PS512":
		bits := opts.RSABits
		if bits == 0 {
			bits = DefaultRSABits
		}
		if bits < MinRSABits {
			return nil, fmt.Errorf("RSA key size must be at least %d bits, got %d", MinRSABits, bits)
		}
		key, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			return nil, err
		}
		return encodeAsymmetric(alg, key, &key.PublicKey)

	case "ES256", "ES384", "ES512":
		var curve elliptic.Curve
		switch alg {
		case "ES256":
			curve = elliptic.P256()
		case "ES384":
			curve = elliptic.P384()
		case "ES512":
			curve = elliptic.P521()
		}
		key, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			return nil, err
		}
		return encodeAsymmetric(alg, key, &key.PublicKey)

	case "EDDSA":
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		return encodeAsymmetric("EdDSA", priv, pub)

	case "NONE", "":
		return nil, errors.New("alg \"none\" does not use a key")

	default:
		return nil, errors.New("unsupported algorithm: " + opts.Algorithm)
	}
}

func generateHMAC(alg string, secretBytes int) (*GeneratedKey, error) {
	min := hmacSecretMinBytes(alg)
	n := secretBytes
	if n == 0 {
		n = min
	}
	if n < min {
		return nil, fmt.Errorf("%s secret must be at least %d bytes (the MAC output size), got %d", alg, min, n)
	}

	secret := make([]byte, n)
	if _, err := rand.Read(secret); err != nil {
		return nil, err
	}
	return &GeneratedKey{Algorithm: alg, Secret: secret}, nil
}

func encodeAsymmetric(alg string, priv crypto.PrivateKey, pub crypto.PublicKey) (*GeneratedKey, error) {
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("marshaling private key: %w", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("marshaling public key: %w", err)
	}

	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

	return &GeneratedKey{
		Algorithm:  alg,
		PrivateKey: priv,
		PublicKey:  pub,
		PrivatePEM: privPEM,
		PublicPEM:  pubPEM,
	}, nil
}
