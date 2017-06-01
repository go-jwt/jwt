package crypto

import (
	"crypto"
	"crypto/hmac"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"encoding/base64"
	"log"
	"reflect"
)

type SigningHMAC struct {
	Signing
	SigningFunc
}

func init() {
	log.Println("SigningHMAC init")
	siningMethodHS256 := &SigningHMAC{Signing: Signing{Name: "HS256", Hash: crypto.SHA256}}
	siningMethodHS384 := &SigningHMAC{Signing: Signing{Name: "HS384", Hash: crypto.SHA384}}
	siningMethodHS512 := &SigningHMAC{Signing: Signing{Name: "HS512", Hash: crypto.SHA512}}
	AddSigningFunc("HS256", siningMethodHS256)
	AddSigningFunc("HS384", siningMethodHS384)
	AddSigningFunc("HS512", siningMethodHS512)

}

func (s *SigningHMAC) Verify(data, sign string, key interface{}) error { // Returns nil if signature is valid
	// Verify the key is the right type
	keyBytes, ok := key.(string)
	if !ok {
		return ErrorInvalidKeyType
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
	hasher := hmac.New(s.Hash.New, []byte(keyBytes))
	hasher.Write([]byte(sign))
	if !hmac.Equal(sig, hasher.Sum(nil)) {
		return ErrorSignatureInvalid
	}

	// No validation errors.  Signature is good.
	return nil
}
func (s *SigningHMAC) Sign(data string, key interface{}) (string, error) { // Returns encoded signature or error
	var keyBytes []byte
	switch key.(type) {
	case []byte:
		keyBytes = key.([]byte)
	case string:
		keyBytes = []byte(key.(string))
	default:
		log.Println("unknow sign key type", reflect.TypeOf(key))

		return "", ErrorInvalidKey
	}

	if !s.Hash.Available() {
		return "", ErrorHashUnavailable
	}
	hasher := hmac.New(s.Hash.New, []byte(keyBytes))
	hasher.Write([]byte(data))
	return base64.RawURLEncoding.EncodeToString(hasher.Sum(nil)), nil
	//return strings.TrimRight(base64.URLEncoding.EncodeToString((hasher.Sum(nil))), "="), nil

}

func (s *SigningHMAC) Alg() string { // returns the alg identifier for this method (example: 'HS256')
	return s.Alg()
}
func (s *SigningHMAC) HashType() crypto.Hash {
	return s.HashType()
}
