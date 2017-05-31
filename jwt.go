package jwt

import (
	"strings"

	"fmt"

	"github.com/go-jwt/jwt/crypto"
)

type JWT interface {
	Header() *Header
	Claims() *Claims
}

type Token struct {
	Header *Header
	Claims *Claims
	Token  string
}

func NewToken(claims *Claims, header *Header) *Token {
	t := new(Token)
	t.Header = header
	t.Claims = claims
	return t
}

func (t *Token) Serialize(key interface{}) ([]byte, error) {
	hb, _ := t.Header.Base64()
	cb, _ := t.Claims.Base64()

	raw := stringConnection(string(hb), string(cb))
	fmt.Println(t.Header.Alg(), raw)
	rlt := crypto.GetSigningMethodFunc(t.Header.Alg())
	fmt.Println(rlt)

	sign, _ := rlt.Sign([]byte(raw), key)
	fmt.Println(sign)
	return []byte(""), nil
}

func stringConnection(s ...string) string {
	return strings.Join(s, ".")
}
