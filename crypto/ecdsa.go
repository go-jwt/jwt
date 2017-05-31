package crypto

import (
	"crypto"
	"crypto/hmac"
	"fmt"
)

type SigningMethodECDSA struct {
	SigningMethod
	SigningMethodFunc
}

var (
	signingMethodES256 *SigningMethodECDSA
	signingMethodES384 *SigningMethodECDSA
	signingMethodES512 *SigningMethodECDSA
)

func init() {
	fmt.Println("second")

	signingMethodES256 = &SigningMethodECDSA{SigningMethod: SigningMethod{Name: "ES256", Hash: crypto.SHA256}}
	signingMethodES384 = &SigningMethodECDSA{SigningMethod: SigningMethod{Name: "ES384", Hash: crypto.SHA384}}
	signingMethodES512 = &SigningMethodECDSA{SigningMethod: SigningMethod{Name: "ES512", Hash: crypto.SHA512}}
	AddSigningMethodFunc("ES256", signingMethodES256)
	AddSigningMethodFunc("ES384", NewECDSA("ES384", crypto.SHA384))
	AddSigningMethodFunc("ES512", NewECDSA("ES512", crypto.SHA512))
	//signingMethod["ES256"] = &SigningMethod{"ES256", crypto.SHA256}
	//signingMethod["ES384"] = &SigningMethod{"ES384", crypto.SHA384}
	//signingMethod["ES512"] = &SigningMethod{"ES512", crypto.SHA512}
}

func NewECDSA(name string, hash crypto.Hash) *SigningMethodECDSA { // Returns nil if signature is valid
	sm := new(SigningMethodECDSA)
	sm.Name = name
	sm.Hash = hash
	return sm
}

func (s *SigningMethodECDSA) Verify(signingString, signature string, key interface{}) error { // Returns nil if signature is valid
	return nil
}
func (s *SigningMethodECDSA) Sign(data []byte, key interface{}) ([]byte, error) { // Returns encoded signature or error
	keyBytes, ok := key.([]byte)
	if !ok {
		return nil, ErrorInvalidKey
	}
	fmt.Println("hash", s.Hash.New())
	hasher := hmac.New(s.Hash.New, keyBytes)
	hasher.Write(data)
	return hasher.Sum(nil), nil
}
func (s *SigningMethodECDSA) Alg() string { // returns the alg identifier for this method (example: 'HS256')
	return s.Name
}
func (s *SigningMethodECDSA) Hasher() crypto.Hash {
	return s.Hash
}
