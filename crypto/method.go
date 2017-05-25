package crypto

import "crypto"

type SigningMethod struct {
	Name string
	Hash crypto.Hash
	//_    struct{}
}

func (sm * SigningMethod)Alg() string {
	return sm.Name
}

