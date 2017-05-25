package jwe

//https://tools.ietf.org/html/rfc7516
type Encryption interface {
	Encrypt()
	Decrypt()
	KeyBits()
	Name()
}