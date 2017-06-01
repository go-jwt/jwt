package jwt

import "errors"

var (
	// ErrorTokenIsExpired is return when time.Now().Unix() is after
	// the token's "exp" claim.
	ErrorTokenIsExpired = errors.New("token is expired")

	// ErrorTokenNotYetValid is return when time.Now().Unix() is before
	// the token's "nbf" claim.
	ErrorTokenNotYetValid = errors.New("token is not yet valid")

	// ErrorInvalidISSClaim means the "iss" claim is invalid.
	ErrorInvalidISSClaim = errors.New("claim \"iss\" is invalid")

	// ErrorInvalidSUBClaim means the "sub" claim is invalid.
	ErrorInvalidSUBClaim = errors.New("claim \"sub\" is invalid")

	// ErrorInvalidIATClaim means the "iat" claim is invalid.
	ErrorInvalidIATClaim = errors.New("claim \"iat\" is invalid")

	// ErrorInvalidJTIClaim means the "jti" claim is invalid.
	ErrorInvalidJTIClaim = errors.New("claim \"jti\" is invalid")

	// ErrorInvalidAUDClaim means the "aud" claim is invalid.
	ErrorInvalidAUDClaim = errors.New("claim \"aud\" is invalid")
)
