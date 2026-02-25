package jwt

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

// LoadPublicKeyFromPEM parses PEM-encoded public key data and returns the key.
// Supported PEM block types:
//   - "PUBLIC KEY" (PKIX/SPKI): RSA, EC, or Ed25519
//   - "RSA PUBLIC KEY" (PKCS#1): RSA only
func LoadPublicKeyFromPEM(pemData []byte) (interface{}, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}

	switch block.Type {
	case "PUBLIC KEY":
		key, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		switch k := key.(type) {
		case *rsa.PublicKey, *ecdsa.PublicKey, ed25519.PublicKey:
			return k, nil
		default:
			return nil, errors.New("unsupported public key type")
		}
	case "RSA PUBLIC KEY":
		return x509.ParsePKCS1PublicKey(block.Bytes)
	default:
		return nil, errors.New("unsupported PEM block type: " + block.Type)
	}
}

// LoadPrivateKeyFromPEM parses PEM-encoded private key data and returns the key.
// Supported PEM block types:
//   - "PRIVATE KEY" (PKCS#8): RSA, EC, or Ed25519
//   - "RSA PRIVATE KEY" (PKCS#1): RSA only
//   - "EC PRIVATE KEY" (SEC 1): EC only
func LoadPrivateKeyFromPEM(pemData []byte) (interface{}, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}

	switch block.Type {
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		switch k := key.(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey:
			return k, nil
		default:
			return nil, errors.New("unsupported private key type")
		}
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	default:
		return nil, errors.New("unsupported PEM block type: " + block.Type)
	}
}
