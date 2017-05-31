package crypto

import "crypto"

type SigningMethodRSA struct {
	SigningMethod
	SigningMethodFunc
}

func init() {
	//AddSigningMethodFunc("RS256", NewRSA("RS256", crypto.SHA256))
	//AddSigningMethodFunc("RS384", NewRSA("RS384", crypto.SHA384))
	//AddSigningMethodFunc("RS512", NewRSA("RS512", crypto.SHA512))
}

func NewRSA(name string, hash crypto.Hash) *SigningMethodRSA { // Returns nil if signature is valid
	sm := new(SigningMethodRSA)
	sm.Name = name
	sm.Hash = hash
	return sm
}
