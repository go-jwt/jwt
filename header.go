package jwt

//jose header
type Header struct {
	HeaderData map[HeaderTypes]interface{}
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
func (h *Header) Register(types HeaderTypes, v ...interface{}) {
	h.HeaderData[types] = v
}

func (h *Header) Get(types HeaderTypes) interface{} {
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
