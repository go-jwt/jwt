package crypto

import "crypto"

type SigningMethod struct {
	Name string
	Hash crypto.Hash
	//_    struct{}
}

type SigningMethodFunc interface {
	Verify(signingString, signature string, key interface{}) error // Returns nil if signature is valid
	Sign(signingString string, key interface{}) (string, error)    // Returns encoded signature or error
	Alg() string                                                   // returns the alg identifier for this method (example: 'HS256')
}

func (sm *SigningMethod) Alg() string {
	return sm.Name
}

type SigningMethodNames string

var signingMethod map[SigningMethodNames]*SigningMethod

func init() {
	MakeMethodNames()
}

func MakeMethodNames() {
	if signingMethod == nil {
		signingMethod = make(map[SigningMethodNames]*SigningMethod)
	}
}

func AddSigningMethod(names SigningMethodNames, method *SigningMethod) {
	MakeMethodNames()
	signingMethod[names] = method
}
