package jwt

import (
	"encoding/json"
	"fmt"

	"github.com/go-jwt/jwt/crypto"
)

//jose header
type Header struct {
	HeaderData map[HeaderTypes]interface{}
	//alg        string
}

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
	h := new(Header)
	h.HeaderData = make(map[HeaderTypes]interface{}, HeaderMax)

	return h
}

func NewJWTHeader(v ...interface{}) *Header {
	h := NewHeader()
	h.Register("typ", "JWT")
	if len(v) == 1 {
		if v, b := v[0].(string); b {
			h.Register("alg", v)
		}
	}
	return h
}

func (h *Header) Register(types HeaderTypes, v ...interface{}) {
	if len(v) == 1 {
		h.HeaderData[types] = v[0]
		return
	}
	h.HeaderData[types] = v

}

func (h *Header) Find(types HeaderTypes) interface{} {
	if h == nil {
		return nil
	}
	return h.HeaderData[types]

}

func (h *Header) Remove(types HeaderTypes) {
	delete(h.HeaderData, types)
}

func (h *Header) Has(types HeaderTypes) bool {
	_, flag := h.HeaderData[types]
	return flag
}

func (h *Header) Base64() string {
	b, e := json.Marshal(h.HeaderData)
	if e != nil {
		return ""
	}
	return Base64Encode(b)
}

func ParseHeader(ser string) (*Header, error) {
	header := new(Header)
	e := ParseBase64(ser, &header.HeaderData)
	if e != nil {
		return nil, e
	}
	return header, nil

}

func (h *Header) Alg() crypto.SigningNames {

	if v, b := h.HeaderData["alg"]; b == true {
		if v, b := v.(string); b == true {
			fmt.Println("header alg", v)
			names := crypto.SigningNames(v)
			return names
		}
		return "none"
	}
	return "none"
}
