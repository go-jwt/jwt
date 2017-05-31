package crypto

import "errors"

var (
	// ErrInvalidKey means the key argument passed to SigningMethod.Verify
	// was not the correct type.
	ErrorInvalidKey      = errors.New("key is invalid")
	ErrorInvalidKeyType  = errors.New("key is of invalid type")
	ErrorHashUnavailable = errors.New("the requested hash function is unavailable")
)
