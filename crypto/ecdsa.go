package crypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"encoding/base64"
	"log"
)

type SigningECDSA struct {
	Signing
	KeySize   int
	CurveBits int
	SigningFunc
}

func init() {
	log.Println("SigningECDSA init")
	SigningES256 := &SigningECDSA{Signing: Signing{Name: "ES256", Hash: crypto.SHA256}}
	SigningES384 := &SigningECDSA{Signing: Signing{Name: "ES384", Hash: crypto.SHA384}}
	SigningES512 := &SigningECDSA{Signing: Signing{Name: "ES512", Hash: crypto.SHA512}}
	AddSigningFunc("ES256", SigningES256)
	AddSigningFunc("ES384", SigningES384)
	AddSigningFunc("ES512", SigningES512)

}

func (s *SigningECDSA) Verify(signingString, signature string, key interface{}) error { // Returns nil if signature is valid
	return nil
}
func (s *SigningECDSA) Sign(data string, key interface{}) (string, error) { // Returns encoded signature or error
	if ecdsaKey, ok := key.(*ecdsa.PrivateKey); ok {
		//TODO: check source
		if !s.Hash.Available() {
			return "", ErrorHashUnavailable
		}

		hasher := s.Hash.New()
		hasher.Write([]byte(data))

		if r1, s1, err := ecdsa.Sign(rand.Reader, ecdsaKey, hasher.Sum(nil)); err == nil {
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
