package crypto

import (
	"crypto"
	"crypto/hmac"
	"encoding/base64"
	"errors"
	"math/big"
	"strings"
)

type SigningMethod struct {
	Name              string
	Hash              crypto.Hash
	SigningMethodFunc *SigningMethodFunc
	//_    struct{}
}

type RSPoint struct {
	S *big.Int
	R *big.Int
}

var ErrorInvalidPrivateKey = errors.New("invalid private key")

type SigningMethodFunc interface {
	Verify(signingString, signature string, key interface{}) error // Returns nil if signature is valid
	Sign(signingString []byte, key interface{}) ([]byte, error)    // Returns encoded signature or error
	Alg() string                                                   // returns the alg identifier for this method (example: 'HS256')
	Hasher() crypto.Hash
}

func (sm *SigningMethod) Alg() string {
	return sm.Name
}

type SigningMethodNames string

var (
	signingMethod     map[SigningMethodNames]*SigningMethod
	signingMethodFunc map[SigningMethodNames]SigningMethodFunc
)

func init() {
	MakeSigningMethod()
	MakeSigningMethodFunc()
}

func MakeSigningMethod() map[SigningMethodNames]*SigningMethod {
	if signingMethod == nil {
		signingMethod = make(map[SigningMethodNames]*SigningMethod)
		return signingMethod
	}
	return nil
}
func MakeSigningMethodFunc() map[SigningMethodNames]SigningMethodFunc {
	if signingMethodFunc == nil {
		signingMethodFunc = make(map[SigningMethodNames]SigningMethodFunc)
		return signingMethodFunc
	}
	return nil
}

func AddSigningMethod(names SigningMethodNames, method *SigningMethod) {
	MakeSigningMethod()
	signingMethod[names] = method
}

func AddSigningMethodFunc(names SigningMethodNames, method SigningMethodFunc) {
	MakeSigningMethodFunc()
	signingMethodFunc[names] = method
}

func GetSigningMethod(names SigningMethodNames) *SigningMethod {
	if m, b := signingMethod[names]; b == true {
		return m
	}
	return nil
}

func GetSigningMethodFunc(names SigningMethodNames) SigningMethodFunc {
	if m, b := signingMethodFunc[names]; b == true {
		return m
	}
	return nil
}

//keyBytes, ok := key.([]byte)
//if !ok {
//return nil, ErrInvalidKey
//}
//hasher := hmac.New(m.Hash.New, keyBytes)
//hasher.Write(data)
//return Signature(hasher.Sum(nil)), nil
func (s *SigningMethod) Sign(data string, key interface{}) ([]byte, error) {

	if keyBytes, ok := key.([]byte); ok {
		if !s.Hash.Available() {
			return []byte(""), ErrorHashUnavailable
		}

		hasher := hmac.New(s.Hash.New, keyBytes)
		hasher.Write([]byte(data))

		return []byte(strings.TrimRight(base64.URLEncoding.EncodeToString((hasher.Sum(nil))), "=")), nil
	}

	return []byte(""), ErrorInvalidKey

	//ecdsaKey, ok := key.(*ecdsa.PrivateKey)
	//if !ok {
	//	return nil, ErrorInvalidPrivateKey
	//}
	//
	//r1, s1, err := ecdsa.Sign(rand.Reader, ecdsaKey, s.hashSum([]byte(data)))
	//if err != nil {
	//	return nil, err
	//}
	//
	//signature, err := asn1.Marshal(RSPoint{R: r1, S: s1})
	//if err != nil {
	//	return nil, err
	//}
	//return signature, nil
}

func (s *SigningMethod) hashSum(b []byte) []byte {
	h := s.Hash.New()
	h.Write(b)
	return h.Sum(nil)
}

func (s *SigningMethod) Hasher() crypto.Hash {
	return s.Hash
}
