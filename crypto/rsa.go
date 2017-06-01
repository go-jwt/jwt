package crypto

import "crypto"

type SigningRSA struct {
	Signing
	SigningFunc
}

func init() {
	//AddSigningFunc("RS256", NewRSA("RS256", crypto.SHA256))
	//AddSigningFunc("RS384", NewRSA("RS384", crypto.SHA384))
	//AddSigningFunc("RS512", NewRSA("RS512", crypto.SHA512))
}

func NewRSA(name string, hash crypto.Hash) *SigningRSA { // Returns nil if signature is valid
	sm := new(SigningRSA)
	sm.Name = name
	sm.Hash = hash
	return sm
}
