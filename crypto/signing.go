package crypto

import (
	"crypto"
)

type Signing struct {
	Name string
	Hash crypto.Hash
}

type SigningFunc interface {
	Verify(data, sign string, key interface{}) error   // Returns nil if string is valid
	Sign(data string, key interface{}) (string, error) // Returns encoded string or error
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

func AddSigningFunc(names SigningNames, method SigningFunc) {
	MakeSigningFunc()
	signingFunc[names] = method
}

func GetSigningFunc(names SigningNames) (SigningFunc, error) {
	if m, b := signingFunc[names]; b == true {
		return m, nil
	}
	return nil, ErrorInvalidSign
}
