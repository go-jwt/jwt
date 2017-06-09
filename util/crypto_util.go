package util

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"log"
)

// ECDSA parsing errors.
var (
	ErrorKeyMustBePEMEncoded = errors.New("key must be pem encoded")
	ErrorNotECPublicKey      = errors.New("Key is not a valid ECDSA public key")
	ErrorNotECPrivateKey     = errors.New("Key is not a valid ECDSA private key")
	ErrorNotRSAPrivateKey    = errors.New("Key is not a valid RSA private key")
	ErrorNotRSAPublicKey     = errors.New("Key is not a valid RSA public key")
)

// ParseECPrivateKeyFromPEM will parse a PEM encoded EC Private
// Key Structure.
func ParseECPrivateKeyFromPEM(key []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(key)
	if block == nil {
		return nil, ErrorKeyMustBePEMEncoded
	}

	// Parse the key

	if parsedKey, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return parsedKey, nil
	} else {
		log.Println(err)
	}
	return nil, ErrorNotECPrivateKey

}

// ParseECPublicKeyFromPEM will parse a PEM encoded PKCS1 or PKCS8 public key
func ParseECPublicKeyFromPEM(key []byte) (*ecdsa.PublicKey, error) {

	block, _ := pem.Decode(key)
	if block == nil {
		return nil, ErrorKeyMustBePEMEncoded
	}

	parsedKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		parsedKey = cert.PublicKey
	}

	if pkey, ok := parsedKey.(*ecdsa.PublicKey); ok {
		return pkey, nil

	}
	return nil, ErrorNotECPublicKey
}

// Parse PEM encoded PKCS1 or PKCS8 private key
func ParseRSAPrivateKeyFromPEM(key []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(key)
	if block == nil {
		return nil, ErrorKeyMustBePEMEncoded
	}

	pkey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		if parsedKey, err := x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
			var ok bool
			if pkey, ok = parsedKey.(*rsa.PrivateKey); !ok {
				return nil, ErrorNotRSAPrivateKey
			}
		}
	}
	return pkey, nil
}

// Parse PEM encoded PKCS1 or PKCS8 public key
func ParseRSAPublicKeyFromPEM(key []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(key)
	if block == nil {
		return nil, ErrorKeyMustBePEMEncoded
	}

	// Parse the key
	parsedKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
			parsedKey = cert.PublicKey
		} else {
			return nil, err
		}
	}

	if pkey, ok := parsedKey.(*rsa.PublicKey); ok {
		return pkey, nil
	}

	return nil, ErrorNotRSAPublicKey

}
