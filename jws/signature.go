package jws

//https://tools.ietf.org/html/rfc7515

type Signature interface {
	Verify()
	Sign()
	Name()
}
