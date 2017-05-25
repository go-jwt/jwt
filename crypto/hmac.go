package crypto

import "crypto"

func init() {
	AddSigningMethod("HS256", &SigningMethod{"HS256", crypto.SHA256})
	AddSigningMethod("HS384", &SigningMethod{"HS384", crypto.SHA384})
	AddSigningMethod("HS512", &SigningMethod{"HS512", crypto.SHA512})
}
