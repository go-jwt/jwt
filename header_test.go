package jwt

import (
	"fmt"
	"testing"
)

func TestHeader_Register(t *testing.T) {
	header := NewHeader()
	header.Register(HEADER_TYPE, "JWT")
	header.Register(HEADER_ALGORITHM, "HS256")
	b, _ := header.Base64()
	fmt.Println(string(b))
	//eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
}
