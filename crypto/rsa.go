package crypto

import "crypto"

func init() {
	AddSigningMethod("RS256", &SigningMethod{"RS256", crypto.SHA256})
	AddSigningMethod("RS384", &SigningMethod{"RS384", crypto.SHA384})
	AddSigningMethod("RS512", &SigningMethod{"RS512", crypto.SHA512})
}
