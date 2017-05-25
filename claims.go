package jwt

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

func (c *Claims) Get(names ClaimNames) interface{} {
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
