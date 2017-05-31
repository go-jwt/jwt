package jwt

import (
	"encoding/json"
	"fmt"
)

type Claims struct {
	ClaimData map[ClaimNames]interface{}
}

type ClaimNames string

const ClaimMax = 7
const (
	CLAIM_ISSUER          ClaimNames = "iss"
	CLAIM_SUBJECT         ClaimNames = "sub"
	CLAIM_AUDIENCE        ClaimNames = "aud"
	CLAIM_EXPIRATION_TIME ClaimNames = "exp"
	CLAIM_NOT_BEFORE      ClaimNames = "nbf"
	CLAIM_ISSUED_AT       ClaimNames = "iat"
	CLAIM_JWT_ID          ClaimNames = "jti"
)

func NewClaims() *Claims {
	claims := new(Claims)
	claims.ClaimData = make(map[ClaimNames]interface{}, ClaimMax)
	return claims
}
func (c *Claims) Register(names ClaimNames, v ...interface{}) {
	c.ClaimData[names] = v
}

//register name
func (c *Claims) RegisterAud(v ...interface{}) {
	c.Register(CLAIM_AUDIENCE, v...)
}
func (c *Claims) RegisterSub(v ...interface{}) {
	c.Register(CLAIM_SUBJECT, v...)
}
func (c *Claims) RegisterIss(v ...interface{}) {
	c.Register(CLAIM_ISSUER, v...)
}
func (c *Claims) RegisterExp(v ...interface{}) {
	c.Register(CLAIM_EXPIRATION_TIME, v...)
}
func (c *Claims) RegisterNbf(v ...interface{}) {
	c.Register(CLAIM_NOT_BEFORE, v...)
}
func (c *Claims) RegisterIat(v ...interface{}) {
	c.Register(CLAIM_ISSUED_AT, v...)
}
func (c *Claims) RegisterJti(v ...interface{}) {
	c.Register(CLAIM_JWT_ID, v...)
}
func (c *Claims) Find(names ClaimNames) interface{} {
	if c == nil {
		return nil
	}
	return c.ClaimData[names]
}

func (c *Claims) Remove(names ClaimNames) {
	delete(c.ClaimData, names)
}

func (c *Claims) Has(names ClaimNames) bool {
	_, flag := c.ClaimData[names]
	return flag
}

func (c *Claims) VerifyAudience(v string) {

}

func (c *Claims) Base64() ([]byte, error) {
	b, e := json.Marshal(c.ClaimData)
	fmt.Println(c.ClaimData)
	if e != nil {
		return nil, e
	}
	return Base64Encode(b), nil

}

func verifyAudience(lef, rig interface{}) bool {
	switch lef.(type) {
	case string:
		l1 := lef.(string)
		if r1, flag := rig.(string); flag {
			return l1 == r1
		}
		r2, flag := rig.([]string)
		return flag && verifyInArray(l1, r2)
	case []string:
		l2 := lef.([]string)
		if r1, flag := rig.(string); flag {
			return l2[0] == r1
		}
		r2, flag := rig.([]string)
		return flag && verifyArraies(l2, r2)
	}
	return false
}

func verifyInArray(lef string, rig []string) bool {
	for _, v := range rig {
		if lef == v {
			return true
		}
	}
	return false
}

func verifyArraies(lef, rig []string) bool {
	s := len(lef)
	if s > len(rig) {
		return false
	}

	f := 0
	for _, lefv := range lef {
		for _, rigv := range rig {
			if lefv == rigv {
				f++
				break

			}
		}
	}
	if s != f {
		return false
	}
	return true

}
