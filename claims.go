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
	tmp := (Claims)(make(map[ClaimNames]interface{}, ClaimMax))

	return &tmp
}

func (c *Claims) Register(names ClaimNames, v interface{}) {
	if c == nil {
		c = NewClaims()
	}
	(*c)[names] = v
}
func (c *Claims) RegisterByTime(names ClaimNames, time time.Time) {
	(*c)[names] = time.Unix()

}

func (c *Claims) Find(names ClaimNames) (v interface{}, b bool) {
	if c != nil {
		v, b = (*c)[names]
	}

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
func (c *Claims) JWTID() (string, bool) {
	return c.FindToString(CLAIM_JWT_ID)
}
func (c *Claims) Base64() string {
	b, e := json.Marshal(*c)
	if e != nil {
		return ""
	}
	return Base64Encode(b)

}

func (c *Claims) ValidateIssuer(jwt JWT) error {
	if v, ok := jwt.Claims().Issuer(); ok {
		if v2, ok2 := c.Issuer(); ok2 && v2 != v {
			util.Debug(v, v2)
			return ErrorInvalidISSClaim
		}
	}
	return nil

}

func (c *Claims) ValidateExpiration(jwt JWT) error {
	if exp, b := c.Expiration(); b {
		if t := time.Now(); exp.Before(t) {
			util.Debug(exp, t)
			return ErrorTokenIsExpired
		}
	}
	return nil
}

func (c *Claims) ValidateIssuedAt(jwt JWT) error {
	if v, ok := jwt.Claims().IssuedAt(); ok {
		if v2, ok2 := c.IssuedAt(); ok2 && !v2.Equal(v) {
			util.Debug(v, v2)
			return ErrorInvalidIATClaim
		}
	}
	return nil
}

func (c *Claims) ValidateSubject(jwt JWT) error {
	if v, ok := jwt.Claims().Subject(); ok {
		if v2, ok2 := c.Subject(); ok2 && v2 != v {
			util.Debug(v, v2)
			return ErrorInvalidSUBClaim
		}
	}
	return nil
}

func (c *Claims) ValidateJWTID(jwt JWT) error {
	if v, ok := jwt.Claims().JWTID(); ok {
		if v2, ok2 := c.JWTID(); ok2 && v2 != v {
			util.Debug(v, v2)
			return ErrorInvalidJTIClaim
		}
	}
	return nil
}

func (c *Claims) ValidateAudience(jwt JWT) error {
	if v, ok := jwt.Claims().Audience(); ok {
		if v2, ok2 := c.Audience(); ok2 {
			if e := util.ArrayCompare(v, v2); e != nil {
				util.Debug(e, v, v2)
				return ErrorInvalidAUDClaim
			}
		}
	}
	return nil
}

func (c *Claims) ValidateNotBefore(jwt JWT) error {
	if nbf, b := c.NotBefore(); b {
		if t := time.Now(); nbf.After(t) {
			util.Debug(nbf, t)
			return ErrorTokenNotYetValid
		}
	}
	return nil
}

func (c *Claims) Validate(jwt JWT) error {
	if e := c.ValidateExpiration(jwt); e != nil {
		return e
	}

	if e := c.ValidateNotBefore(jwt); e != nil {
		return e
	}

	if e := c.ValidateAudience(jwt); e != nil {
		return e
	}

	if e := c.ValidateIssuedAt(jwt); e != nil {
		return e
	}
	if e := c.ValidateIssuer(jwt); e != nil {
		return e
	}
	if e := c.ValidateJWTID(jwt); e != nil {
		return e
	}

	if e := c.ValidateSubject(jwt); e != nil {
		return e
	}
	return nil
}

func ParseClaims(ser string) (*Claims, error) {
	claims := new(Claims)
	e := ParseBase64(ser, claims)
	if e != nil {
		return nil, e
	}
	return claims, nil

}
