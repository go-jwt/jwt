package crypto

import (
	"crypto"
	"math/big"
)

type Signing struct {
	Name        string
	Hash        crypto.Hash
	SigningFunc *SigningFunc
	//_    struct{}
}

type RSPoint struct {
	S *big.Int
	R *big.Int
}

type SigningFunc interface {
	Verify(data, sign string, key interface{}) error   // Returns nil if signature is valid
	Sign(data string, key interface{}) (string, error) // Returns encoded signature or error
	Alg() string                                       // returns the alg identifier for this method (example: 'HS256')
	HashType() crypto.Hash
}

func (s *Signing) Alg() string {
	return s.Name
}

func (s *Signing) HashType() crypto.Hash {
	return s.Hash
}

type SigningNames string

var (
	signing     map[SigningNames]*Signing
	signingFunc map[SigningNames]SigningFunc
)

func init() {
	MakeSigning()
	MakeSigningFunc()
}

func MakeSigning() map[SigningNames]*Signing {
	if signing == nil {
		signing = make(map[SigningNames]*Signing)
		return signing
	}
	return nil
}
func MakeSigningFunc() map[SigningNames]SigningFunc {
	if signingFunc == nil {
		signingFunc = make(map[SigningNames]SigningFunc)
		return signingFunc
	}
	return nil
}

//func AddSigning(names SigningNames, method *Signing) {
//	MakeSigning()
//	signing[names] = method
//}

func AddSigningFunc(names SigningNames, method SigningFunc) {
	MakeSigningFunc()
	signingFunc[names] = method
}

//
//func GetSigning(names SigningNames) *Signing {
//	if m, b := signing[names]; b == true {
//		return m
//	}
//	return nil
//}

func GetSigningFunc(names SigningNames) (SigningFunc, error) {
	if m, b := signingFunc[names]; b == true {
		return m, nil
	}
	return nil, ErrorInvalidSign
}
