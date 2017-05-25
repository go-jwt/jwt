package jws

//https://tools.ietf.org/html/rfc7515
//jose header
type Header struct {
	HeaderData map[HeaderType]interface{}
}

type HeaderType string

const HeaderMax = 11
const (
	HEADER_ALGORITHM                          HeaderType = "alg"
	HEADER_JWK_SET_URL                        HeaderType = "jku"
	HEADER_JSON_WEB_KEY                       HeaderType = "jwk"
	HEADER_KEY_ID                             HeaderType = "kid"
	HEADER_X509_URL                           HeaderType = "x5u"
	HEADER_X509_CERTIFICATE_CHAIN             HeaderType = "x5c"
	HEADER_X509_CERTIFICATE_SHA1_THUMBPRINT   HeaderType = "x5t"
	HEADER_X509_CERTIFICATE_SHA256_THUMBPRINT HeaderType = "x5t#S256"
	HEADER_TYPE                               HeaderType = "typ"
	HEADER_CONTENT_TYPE                       HeaderType = "cty"
	HEADER_CRITICAL                           HeaderType = "crit"
)

func NewHeader() {
	h := new(Header)
	h.HeaderData = make(map[HeaderType]interface{}, HeaderMax)
}
func (h *Header) Register(headerType HeaderType, v ...interface{}) {

}
