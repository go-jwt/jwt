package jwt

import "testing"

func TestClaims_Register(t *testing.T) {
	NewClaims().Register(CLAIM_SUBJECT,"123")
}
