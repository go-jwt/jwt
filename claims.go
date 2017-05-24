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
func (c *Claims) Register(cn ClaimNames, v ...string) {
	c.ClaimData[cn] = v
}
