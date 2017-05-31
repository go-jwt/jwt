package crypto

import (
	"crypto"
	"crypto/hmac"
	"encoding/base64"
	"fmt"
	"strings"
)

type SigningMethodHMAC struct {
	SigningMethod
	SigningMethodFunc
}

var (
	siningMethodHS256 *SigningMethodHMAC
	siningMethodHS384 *SigningMethodHMAC
	siningMethodHS512 *SigningMethodHMAC
)

func init() {
	fmt.Println("first")
	siningMethodHS256 = &SigningMethodHMAC{SigningMethod: SigningMethod{Name: "HS256", Hash: crypto.SHA256}}
	siningMethodHS384 = &SigningMethodHMAC{SigningMethod: SigningMethod{Name: "HS384", Hash: crypto.SHA256}}
	siningMethodHS256 = &SigningMethodHMAC{SigningMethod: SigningMethod{Name: "HS256", Hash: crypto.SHA256}}
	//AddSigningMethodFunc("HS256", &SigningMethodHMAC{SigningMethod: SigningMethod{Name: "HS256", Hash: crypto.SHA256}})
	//AddSigningMethodFunc("HS384", NewHMAC("HS384", crypto.SHA384))
	//AddSigningMethodFunc("HS512", NewHMAC("HS512", crypto.SHA512))
}

func NewHMAC(name string, hash crypto.Hash) *SigningMethodHMAC { // Returns nil if signature is valid
	sm := new(SigningMethodHMAC)
	sm.Name = name
	sm.Hash = hash
	fmt.Println(hash.New())
	return sm
}

func (s *SigningMethodHMAC) Verify(signingString, signature string, key interface{}) error { // Returns nil if signature is valid
	return nil
}
func (s *SigningMethodHMAC) Sign(data []byte, key interface{}) ([]byte, error) { // Returns encoded signature or error

	if keyBytes, ok := key.([]byte); ok {
		if !s.Hash.Available() {
			return []byte(""), ErrorHashUnavailable
		}

		hasher := hmac.New(s.Hash.New, keyBytes)
		hasher.Write(data)

		return []byte(strings.TrimRight(base64.URLEncoding.EncodeToString((hasher.Sum(nil))), "=")), nil
	}

	return []byte(""), ErrorInvalidKey

}

func (s *SigningMethodHMAC) Alg() string { // returns the alg identifier for this method (example: 'HS256')
	return s.Alg()
}
func (s *SigningMethodHMAC) Hasher() crypto.Hash {
	return s.Hasher()
}
