package jwt

import (
	"encoding/base64"
	"encoding/json"
)

//from https://github.com/SermoDigital/jose/blob/master/base64.go
// Base64Decode
func Base64Decode(b string) ([]byte, error) {
	buf := make([]byte, base64.RawURLEncoding.DecodedLen(len(b)))
	n, err := base64.RawURLEncoding.Decode(buf, []byte(b))
	return buf[:n], err
}

// Base64Encode
func Base64Encode(b []byte) string {
	buf := make([]byte, base64.RawURLEncoding.EncodedLen(len(b)))
	base64.RawURLEncoding.Encode(buf, b)
	return string(buf)
}

func EncodeEscape(b []byte) []byte {
	buf := make([]byte, base64.RawURLEncoding.EncodedLen(len(b))+2)
	buf[0] = '"'
	base64.RawURLEncoding.Encode(buf[1:], b)
	buf[len(buf)-1] = '"'
	return buf
}

func DecodeEscaped(b []byte) ([]byte, error) {
	if len(b) > 1 && b[0] == '"' && b[len(b)-1] == '"' {
		b = b[1 : len(b)-1]
	}
	return Base64Decode(string(b))
}

func ParseBase64(serialized string, v interface{}) error {
	b, e := Base64Decode(serialized)
	if e != nil {
		return e
	}
	e = json.Unmarshal(b, v)
	if e != nil {
		return e
	}
	return nil
}
