package jwt

import (
	"encoding/json"

	"github.com/go-jwt/jwt/crypto"
)

//type Header struct {
//	HeaderData map[HeaderTypes]interface{}
//	//alg        string
//}

type Header map[HeaderTypes]interface{}

type HeaderTypes string

const HeaderMax = 11
const (
	HEADER_ALGORITHM                          HeaderTypes = "alg"
	HEADER_JWK_SET_URL                        HeaderTypes = "jku"
	HEADER_JSON_WEB_KEY                       HeaderTypes = "jwk"
	HEADER_KEY_ID                             HeaderTypes = "kid"
	HEADER_X509_URL                           HeaderTypes = "x5u"
	HEADER_X509_CERTIFICATE_CHAIN             HeaderTypes = "x5c"
	HEADER_X509_CERTIFICATE_SHA1_THUMBPRINT   HeaderTypes = "x5t"
	HEADER_X509_CERTIFICATE_SHA256_THUMBPRINT HeaderTypes = "x5t#S256"
	HEADER_TYPE                               HeaderTypes = "typ"
	HEADER_CONTENT_TYPE                       HeaderTypes = "cty"
	HEADER_CRITICAL                           HeaderTypes = "crit"
)

func NewHeader() *Header {
	tmp := (Header)(make(map[HeaderTypes]interface{}, HeaderMax))
	return &tmp
}

func NewJWTHeader() *Header {
	h := NewHeader()
	h.Register("typ", "JWT")
	return h
}

func (h *Header) Register(types HeaderTypes, v interface{}) {
	(*h)[types] = v

}

func (h *Header) Find(types HeaderTypes) (interface{}, bool) {
	if v, b := (*c)[types]; b {
		return v, true
	}
	return nil, false
}

func (h *Header) Remove(types HeaderTypes) {
	delete(*h, types)
}

func (h *Header) Has(types HeaderTypes) bool {
	_, flag := (*h)[types]
	return flag
}

func (h *Header) Base64() string {
	b, e := json.Marshal(*h)
	if e != nil {
		return ""
	}
	return Base64Encode(b)
}

func ParseHeader(ser string) (*Header, error) {
	header := new(Header)
	e := ParseBase64(ser, header)
	if e != nil {
		return nil, e
	}
	return header, nil

}

func (h *Header) Alg() crypto.SigningNames {
	if v, b := (*h)["alg"]; b == true {
		if v, b := v.(string); b == true {
			names := crypto.SigningNames(v)
			return names
		}
		return ""
	}
	return ""
}
