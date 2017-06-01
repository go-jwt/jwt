package jwt

import (
	"encoding/json"
	"time"
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
	c.ClaimData[names] = v[0]
}

//register name
func (c *Claims) RegisterAud(v ...interface{}) {
	c.Register(CLAIM_AUDIENCE, v...)
}

func (c *Claims) Audience() ([]string, bool) {
	var r []string
	if v, flag := c.ClaimData[CLAIM_AUDIENCE]; flag == true {
		switch v.(type) {
		case []string:
			r = v.([]string)
		case string:
			r = []string{v.(string)}
		case []interface{}:
			for _, v := range v.([]interface{}) {
				if v1, b := LiteralToString(v); b {
					r = append(r, v1)
				}
			}
		case interface{}:
			if v1, b := LiteralToString(v); b {
				r = append(r, v1)
			}
		default:
			return []string{""}, false
		}
	}
	return r, true

}

func (c *Claims) RegisterSub(v ...interface{}) {
	c.Register(CLAIM_SUBJECT, v...)
}

//func (c *Claims) Subject() (int64, bool) {
//	v, b := c.Find(CLAIM_SUBJECT).(int64)
//	return v, b
//
//}
func (c *Claims) RegisterIss(v ...interface{}) {
	c.Register(CLAIM_ISSUER, v...)
}
func (c *Claims) RegisterExp(t time.Time) {
	c.Register(CLAIM_EXPIRATION_TIME, t.Unix())
}

func (c *Claims) ExpirationTime() (time.Time, bool) {
	v1, b := LiteralToTime(c.Find(CLAIM_EXPIRATION_TIME))
	return v1, b

}

func (c *Claims) RegisterNbf(t time.Time) {
	c.Register(CLAIM_NOT_BEFORE, t.Unix())
}

func (c *Claims) NotBefore() (time.Time, bool) {
	v1, b := LiteralToTime(c.Find(CLAIM_NOT_BEFORE))
	return v1, b

}

func (c *Claims) RegisterIat(t time.Time) {
	c.Register(CLAIM_ISSUED_AT, t.Unix())
}
func (c *Claims) IssuedAt() (time.Time, bool) {
	v1, b := LiteralToTime(c.Find(CLAIM_ISSUED_AT))
	return v1, b

}
func (c *Claims) RegisterJti(v ...interface{}) {
	c.Register(CLAIM_JWT_ID, v...)
}

func (c *Claims) Validate(now time.Time, expLeeway, nbfLeeway time.Duration) error {
	if exp, ok := c.ExpirationTime(); ok {
		if now.After(exp.Add(expLeeway)) {
			return ErrorTokenIsExpired
		}
	}

	if nbf, ok := c.NotBefore(); ok {
		if !now.After(nbf.Add(-nbfLeeway)) {
			return ErrorTokenNotYetValid
		}
	}
	return nil
}

func (c *Claims) Find(names ClaimNames) interface{} {
	if v, b := c.ClaimData[names]; b {
		return v
	}
	return nil
}

func (c *Claims) Remove(names ClaimNames) {
	delete(c.ClaimData, names)
}

func (c *Claims) Has(names ClaimNames) bool {
	_, flag := c.ClaimData[names]
	return flag
}

func LiteralToString(v interface{}) (string, bool) {
	if v, b := v.(string); b {
		return v, true
	}
	if v, b := v.([]byte); b {
		return string(v), true
	}
	return "", false
}

func LiteralToTime(v interface{}) (time.Time, bool) {
	var t int64
	switch v.(type) {
	case int:
		t = int64(v.(int))
	case int32:
		t = int64(v.(int32))
	case int64:
		t = v.(int64)
	case uint:
		t = int64(v.(uint))
	case uint32:
		t = int64(v.(uint32))
	case uint64:
		t = int64(v.(uint64))
	case float64:
		t = int64(v.(float64))
	default:
		return time.Time{}, false
	}

	return time.Unix(t, 0), true
}

func (c *Claims) VerifyAudience(v string) {

}

func (c *Claims) Base64() string {
	b, e := json.Marshal(c.ClaimData)
	if e != nil {
		return ""
	}
	return Base64Encode(b)

}

func ParseClaims(ser string) (*Claims, error) {
	claims := new(Claims)
	e := ParseBase64(ser, &claims.ClaimData)
	if e != nil {
		return nil, e
	}
	return claims, nil

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
