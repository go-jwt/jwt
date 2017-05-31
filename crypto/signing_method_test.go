package crypto

import (
	"crypto"
	"crypto/sha512"
	"fmt"
	"testing"
)

func TestSigningMethod_Alg(t *testing.T) {
	t.Log(signingMethod)
	fmt.Println(crypto.SHA512.New())
	fmt.Println(crypto.SHA384.New())
	fmt.Println(sha512.New())
	fmt.Println(sha512.New384())

}
