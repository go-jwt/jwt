package crypto

import (
	"crypto"
	"crypto/hmac"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"encoding/base64"
	"log"

	"github.com/go-jwt/jwt/util"
)

type SigningHMAC struct {
	Signing
}

func init() {
	log.Println("SigningHMAC init")
	siningMethodHS256 := &SigningHMAC{Signing{"HS256", crypto.SHA256}}
	siningMethodHS384 := &SigningHMAC{Signing{"HS384", crypto.SHA384}}
	siningMethodHS512 := &SigningHMAC{Signing{"HS512", crypto.SHA512}}
	AddSigningFunc("HS256", siningMethodHS256)
	AddSigningFunc("HS384", siningMethodHS384)
	AddSigningFunc("HS512", siningMethodHS512)

}

func (s *SigningHMAC) Verify(data, sign string, key interface{}) error { // Returns nil if signature is valid
	// Verify the key is the right type
	keyBytes, b := util.LiteralToBytes(key)
	if !b {
		return ErrorInvalidKey
	}

	// Decode signature, for comparison
	sig, err := base64.RawURLEncoding.DecodeString(data)
	if err != nil {
		return err
	}

	// Can we use the specified hashing method?
	if !s.Hash.Available() {
		return ErrorHashUnavailable
	}

	// This signing method is symmetric, so we validate the signature
	// by reproducing the signature from the signing string and key, then
	// comparing that against the provided signature.
	hashed := hmac.New(s.Hash.New, []byte(keyBytes))
	hashed.Write([]byte(sign))
	if !hmac.Equal(sig, hashed.Sum(nil)) {
		return ErrorSignatureInvalid
	}

	// No validation errors.  Signature is good.
	return nil
}
func (s *SigningHMAC) Sign(data string, key interface{}) (string, error) { // Returns encoded signature or error
	keyBytes, b := util.LiteralToBytes(key)
	if !b {
		return "", ErrorInvalidKey
	}
	if !s.Hash.Available() {
		return "", ErrorHashUnavailable
	}
	hashed := hmac.New(s.Hash.New, []byte(keyBytes))
	hashed.Write([]byte(data))

	return base64.RawURLEncoding.EncodeToString(hashed.Sum(nil)), nil

}

func (s *SigningHMAC) Alg() string { // returns the alg identifier for this method (example: 'HS256')
	return s.Name
}
func (s *SigningHMAC) HashType() crypto.Hash {
	return s.Hash
}
