package jwt

import (
	"strings"

	"gopkg.in/jwt.v1/crypto"
	"gopkg.in/jwt.v1/util"
)

const (
	TOKEN_HEADER = iota
	TOKEN_CLAIMS
	TOKEN_SIGN
	TOKEN_MAX
)

type JWT interface {
	Header() *Header
	Claims() *Claims
}

type TokenString []string
type KeyByte []byte

type Token interface {
	Verify() error
	Claims() *Claims
	Header() *Header
	Serialize() (string, error)
	SetKey(key interface{})
}

type token struct {
	header *Header
	claims *Claims
	Token  TokenString
	key    interface{}
}

//parse claims header parameters
func NewToken(v ...interface{}) Token {
	token := new(token)
	token.Token = make([]string, TOKEN_MAX)
	if len(v) > 0 {
		for _, v := range v {
			switch v.(type) {
			case *Claims:
				token.claims = v.(*Claims)
				token.Token[TOKEN_CLAIMS] = token.claims.Base64()
				//case Claims:
				//	*token.claims = v.(Claims)
				//	token.Token[TOKEN_CLAIMS] = token.claims.Base64()
			case *Header:
				token.header = v.(*Header)
				token.Token[TOKEN_HEADER] = token.header.Base64()
				//case Header:
				//	*token.header = v.(Header)
				//	token.Token[TOKEN_HEADER] = token.header.Base64()
			case []string:
				token.Token = TokenString(v.([]string))
			case TokenString:
				token.Token = v.(TokenString)
			default:
				util.Debug("key",v)
				token.key = v
			}
		}
	}

	return token
}

func ParseToken(serialized string, key interface{}) (Token, error) {
	util.Debug("ParseToken")
	var err error

	token := stringSegment(serialized)

	header, err := ParseHeader(token[TOKEN_HEADER])
	if err != nil {
		return nil, err
	}
	util.Debug(header)
	claims, err := ParseClaims(token[TOKEN_CLAIMS])
	if err != nil {
		return nil, err
	}
	util.Debug(claims)
	t := NewToken(header, claims, token, key)
	if err = t.Verify(); err != nil {
		return nil, err
	}
	util.Debug(t)
	return t, nil

}

func (t *token) Verify() error {
	raw := stringConnection(t.Token[TOKEN_HEADER], t.Token[TOKEN_CLAIMS])
	f, err := crypto.GetSigningFunc(t.header.Alg())
	if err != nil {
		return err
	}

	err = f.Verify(t.Token[TOKEN_SIGN], raw, t.key)
	return err
}

func (t *token) Claims() *Claims {
	return t.claims
}

func (t *token) Header() *Header {
	return t.header
}

func (t *token) Serialize() (string, error) {

	t.Token[TOKEN_HEADER] = t.header.Base64()
	t.Token[TOKEN_CLAIMS] = t.claims.Base64()

	raw := stringConnection(t.Token[TOKEN_HEADER], t.Token[TOKEN_CLAIMS])
	f, err := crypto.GetSigningFunc(t.header.Alg())
	if err != nil {
		return "", err
	}
	sign, err := f.Sign(raw, t.key)

	if err != nil {
		return "", err
	}
	t.Token[TOKEN_SIGN] = sign

	return stringConnection(t.Token[TOKEN_HEADER], t.Token[TOKEN_CLAIMS], t.Token[TOKEN_SIGN]), nil
}

func (t *token) SetKey(key interface{}) {
	t.key = key
}

func stringConnection(s ...string) string {
	return strings.Join(s, ".")
}

func stringSegment(s string) []string {
	return strings.Split(s, ".")
}
