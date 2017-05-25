package crypto

import (
	"crypto"
	"fmt"
)

type SigningMethodECDSA struct {
}

var (
	signingMethodES256 *SigningMethod
	signingMethodES384 *SigningMethod
	signingMethodES512 *SigningMethod
)

func init() {
	fmt.Println("second")
	AddSigningMethod("ES256", &SigningMethod{"ES256", crypto.SHA256})
	AddSigningMethod("ES384", &SigningMethod{"ES384", crypto.SHA384})
	AddSigningMethod("ES512", &SigningMethod{"ES512", crypto.SHA512})
	//signingMethod["ES256"] = &SigningMethod{"ES256", crypto.SHA256}
	//signingMethod["ES384"] = &SigningMethod{"ES384", crypto.SHA384}
	//signingMethod["ES512"] = &SigningMethod{"ES512", crypto.SHA512}
}
