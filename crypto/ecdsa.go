package crypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"encoding/base64"
	"fmt"
	"log"
	"math/big"
)

var TypeECDSA struct {
	KeySize   int
	CurveBits int
}

type SigningECDSA struct {
	Signing
	KeySize   int
	CurveBits int
}

func init() {
	log.Println("SigningECDSA init")
	SigningES256 := &SigningECDSA{Signing{"ES256", crypto.SHA256}, 32, 256}
	SigningES384 := &SigningECDSA{Signing{"ES384", crypto.SHA384}, 48, 384}
	SigningES512 := &SigningECDSA{Signing{"ES512", crypto.SHA512}, 66, 521}
	AddSigningFunc("ES256", SigningES256)
	AddSigningFunc("ES384", SigningES384)
	AddSigningFunc("ES512", SigningES512)

}

func (s *SigningECDSA) Verify(data, sign string, key interface{}) error { // Returns nil if signature is valid

	var err error

	// Decode the signature
	var sig []byte
	if sig, err = base64.RawURLEncoding.DecodeString(sign); err != nil {
		return err
	}

	// Get the key
	var ecdsaKey *ecdsa.PublicKey
	switch k := key.(type) {
	case *ecdsa.PublicKey:
		ecdsaKey = k
	default:
		return ErrorInvalidKeyType
	}

	if len(sig) != 2*s.KeySize {
		return ErrorECDSAVerification
	}

	r1 := big.NewInt(0).SetBytes(sig[:s.KeySize])
	s1 := big.NewInt(0).SetBytes(sig[s.KeySize:])

	// Create hasher
	if !s.Hash.Available() {
		return ErrorHashUnavailable
	}
	hasher := s.Hash.New()
	hasher.Write([]byte(data))

	// Verify the signature
	if verifystatus := ecdsa.Verify(ecdsaKey, hasher.Sum(nil), r1, s1); verifystatus == true {
		return nil
	} else {
		return ErrorECDSAVerification
	}

}
func (s *SigningECDSA) Sign(data string, key interface{}) (string, error) { // Returns encoded signature or error

	if ecdsaKey, ok := key.(*ecdsa.PrivateKey); ok && ecdsaKey != nil {
		fmt.Println("ecdsaKey", ecdsaKey)
		if !s.Hash.Available() {
			return "", ErrorHashUnavailable
		}

		hashed := s.Hash.New()
		hashed.Write([]byte(data))

		if r1, s1, err := ecdsa.Sign(rand.Reader, ecdsaKey, hashed.Sum(nil)); err == nil {
			curveBits := ecdsaKey.Curve.Params().BitSize

			if s.CurveBits != curveBits {
				return "", ErrorInvalidKey
			}

			keyBytes := curveBits / 8
			if curveBits%8 > 0 {
				keyBytes += 1
			}

			rBytes := r1.Bytes()
			rBytesPadded := make([]byte, keyBytes)
			copy(rBytesPadded[keyBytes-len(rBytes):], rBytes)

			sBytes := s1.Bytes()
			sBytesPadded := make([]byte, keyBytes)
			copy(sBytesPadded[keyBytes-len(sBytes):], sBytes)

			out := append(rBytesPadded, sBytesPadded...)

			return base64.RawURLEncoding.EncodeToString(out), nil
		} else {
			return "", err
		}
	}
	return "", ErrorInvalidKeyType
}
func (s *SigningECDSA) Alg() string { // returns the alg identifier for this method (example: 'HS256')
	return s.Name
}
func (s *SigningECDSA) HashType() crypto.Hash {
	return s.Hash
}
