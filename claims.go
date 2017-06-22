package jwt

import (
	"encoding/json"
	"time"

	"gopkg.in/jwt.v1/util"
)

//type Claims struct {
//	ClaimData map[ClaimNames]interface{}
//}

type Claims map[ClaimNames]interface{}

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
	//claims := new(Claims)
	//claims.ClaimData = make(map[ClaimNames]interface{}, ClaimMax)
	tmp := (Claims)(make(map[ClaimNames]interface{}, ClaimMax))

	return &tmp
}

func (c *Claims) Register(names ClaimNames, v interface{}) {
	//switch v.(type) {
	//case time.Time:
	//	c.ClaimData[names] = v.(time.Time).Unix()
	//	return CaimsErrorTimeFunc
	//default:
	//	c.ClaimData[names] = v
	//}
	(*c)[names] = v

}
func (c *Claims) RegisterByTime(names ClaimNames, time time.Time) {
	(*c)[names] = time.Unix()

}

func (c *Claims) Find(names ClaimNames) (v interface{}, b bool) {
	v, b = (*c)[names]
	return
}

func (c *Claims) FindToTime(names ClaimNames) (time.Time, bool) {
	if v, b := c.Find(names); b {
		return util.LiteralToTime(v)
	}

	return time.Time{}, false
}

func (c *Claims) FindToString(names ClaimNames) (string, bool) {
	if v, b := c.Find(names); b {
		if v, b := v.(string); b {
			return v, true
		}
	}

	return "", false
}

func (c *Claims) Remove(names ClaimNames) {
	delete(*c, names)
}

func (c *Claims) Has(names ClaimNames) bool {
	_, flag := (*c)[names]
	return flag
}

func (c *Claims) RegisterAud(v ...string) {
	c.Register(CLAIM_AUDIENCE, v)
}

/**
 * Returns the JWT <a href="https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-25#section-4.1.3">
 * <code>aud</code></a> (audience) value or {nil} if not present.
 *
 * @return the JWT {[]string,true} value or {nil,false} if not present.
 */
func (c *Claims) Audience() ([]string, bool) {
	if v, flag := c.Find(CLAIM_AUDIENCE); flag {
		if v := util.LiteralToStringArray(v); v != nil {
			return v, true
		}
	}
	return nil, false

}

func (c *Claims) RegisterSub(v string) {
	c.Register(CLAIM_SUBJECT, v)
}

/**
 * Returns the JWT <a href="https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-25#section-4.1.2">
 * <code>sub</code></a> (subject) value or {""} if not present.
 *
 * @return the JWT {sub,true} value or {"",false} if not present.
 */
func (c *Claims) Subject() (string, bool) {
	return c.FindToString(CLAIM_SUBJECT)
}

func (c *Claims) RegisterIss(v string) {
	c.Register(CLAIM_ISSUER, v)
}

/**
 * Returns the JWT <a href="https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-25#section-4.1.1">
 * <code>iss</code></a> (issuer) value or {""} if not present.
 *
 * @return the JWT {iss,true} value or {"",false} if not present.
 */
func (c *Claims) Issuer() (string, bool) {
	return c.FindToString(CLAIM_ISSUER)
}

func (c *Claims) RegisterExp(t time.Time) {
	c.RegisterByTime(CLAIM_EXPIRATION_TIME, t)
}

/**
 * Returns the JWT <a href="https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-25#section-4.1.4">
 * <code>exp</code></a> (expiration) timestamp or {Time{}} if not present.
 *
 * <p>A JWT obtained after this timestamp should not be used.</p>
 *
 * @return the JWT {exp,true} value or {Time{},false} if not present.
 */
func (c *Claims) Expiration() (time.Time, bool) {
	return c.FindToTime(CLAIM_EXPIRATION_TIME)
}

//Expiration's alias
func (c *Claims) ExpirationTime() (time.Time, bool) {
	return c.Expiration()

}

func (c *Claims) RegisterNbf(t time.Time) {
	c.RegisterByTime(CLAIM_NOT_BEFORE, t)
}

/**
 * Returns the JWT <a href="https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-25#section-4.1.5">
 * <code>nbf</code></a> (not before) timestamp or {Time{}} if not present.
 * <p>A JWT obtained before this timestamp should not be used.</p>
 *
 * @return the JWT {nbf,true} value or {Time{},false} if not present.
 */
func (c *Claims) NotBefore() (time.Time, bool) {
	return c.FindToTime(CLAIM_NOT_BEFORE)

}

func (c *Claims) RegisterIat(t time.Time) {
	c.RegisterByTime(CLAIM_ISSUED_AT, t)
}

/**
 * Returns the JWT <a href="https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-25#section-4.1.6">
 * <code>iat</code></a> (issued at) timestamp or {Time{}} if not present.
 *
 * <p>If present, this value is the timestamp when the JWT was created.</p>
 *
 * @return the JWT {nbf,true} value or {Time,false} if not present.
 */
func (c *Claims) IssuedAt() (time.Time, bool) {
	return c.FindToTime(CLAIM_ISSUED_AT)
}

func (c *Claims) RegisterJti(v string) {
	c.Register(CLAIM_JWT_ID, v)
}

/**
 * Returns the JWTs <a href="https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-25#section-4.1.7">
 * <code>jti</code></a> (JWT ID) value or {""} if not present.
 *
 * <p>This value is a CaSe-SenSiTiVe unique identifier for the JWT. If available, this value is expected to be
 * assigned in a manner that ensures that there is a negligible probability that the same value will be
 * accidentally
 * assigned to a different data object.  The ID can be used to prevent the JWT from being replayed.</p>
 *
 * @return the JWT {jti,true} value or {"",false} if not present.
 */
func (c *Claims) JWT_ID() (string, bool) {
	return c.FindToString(CLAIM_JWT_ID)
}
func (c *Claims) Validate(now time.Time, expLeeway, nbfLeeway time.Duration) error {
	if exp, b := c.Expiration(); b {
		if now.After(exp.Add(expLeeway)) {
			return ErrorTokenIsExpired
		}
	}

	if nbf, b := c.NotBefore(); b {
		if !now.After(nbf.Add(-nbfLeeway)) {
			return ErrorTokenNotYetValid
		}
	}
	return nil
}

func (c *Claims) VerifyAudience(v string) {

}

func (c *Claims) Base64() string {
	b, e := json.Marshal(*c)
	if e != nil {
		return ""
	}
	return Base64Encode(b)

}

func ParseClaims(ser string) (*Claims, error) {
	claims := new(Claims)
	e := ParseBase64(ser, claims)
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
