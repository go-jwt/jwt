package jwt

import "testing"

func TestClaims_Register(t *testing.T) {
claims:=NewClaims()
	claims.Register(CLAIM_AUDIENCE, "example.com","api.example.com")

}

func TestClaims_VerifyAudience(t *testing.T) {
	tests := [...]struct {
		a interface{}
		b interface{}
		v bool
	}{
		0: {"https://www.google.com", "https://www.google.com", true},
		1: {[]string{"example.com", "google.com"}, []string{"example.com"}, false},
		2: {500, 43, false},
		3: {"google.com", "facebook.com", false},
		4: {[]string{"example.com"}, []string{"example.com", "foo.com"}, true},
	}
	for i, v := range tests {
		if x := verifyAudience(v.a, v.b); x != v.v {
			t.Fatalf("#%d: wanted %t, got %t", i, v.v, x)
		}
	}
}
