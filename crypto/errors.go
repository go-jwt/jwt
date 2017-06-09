package crypto

import "errors"

var (
	// ErrInvalidKey means the key argument passed to Signing.Verify
	// was not the correct type.
	ErrorInvalidKey       = errors.New("key is invalid")
	ErrorInvalidSign      = errors.New("the signing function is not found")
	ErrorSignatureInvalid = errors.New("signature is invalid")
	ErrorInvalidKeyType   = errors.New("key is of invalid type")
	ErrorHashUnavailable  = errors.New("the requested hash function is unavailable")
	//ErrorTransferString   = errors.New("transfer string error")
	ErrorECDSAVerification = errors.New("crypto/ecdsa: verification error")
	ErrorInvalidPrivateKey = errors.New("invalid private key")
)
