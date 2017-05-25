package jwa


//https://tools.ietf.org/html/rfc7518
type Algorithm interface {
	NewWrap()
	Unwrap()
	Name()
}