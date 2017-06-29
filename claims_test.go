package jwt

import (
	_ "crypto"

	"gopkg.in/jwt.v1/util"

	"io/ioutil"
	"testing"
	"time"

	"gopkg.in/jwt.v1/crypto"
)

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
func TestMultipleAudienceBug_AfterMarshal(t *testing.T) {
	key, _ := ioutil.ReadFile("test/ec512-private.pem")
	// Create JWS claims
	claims := NewClaims()
	claims.RegisterAud("example.com", "api.example.com")

	header := NewHeader()
	header.Register(HEADER_TYPE, "JWT")
	header.Register(HEADER_ALGORITHM, "ES256")

	tk := NewToken(claims, header, key)

	ser, _ := tk.Serialize()

	token, e := ParseToken(ser, key)
	if e != nil {
		t.Logf("%s", e.Error())
		return
	}
	aud, _ := token.Claims().Audience()

	t.Logf("aud Value: %s", aud)
	t.Logf("aud Type : %T", aud)

}

func TestMultipleAudienceFix_AfterMarshal(t *testing.T) {
	// Create JWS claims
	claims := NewClaims()
	claims.RegisterAud("example.com", "api.example.com")
	//"iss": "https://server.example.com",
	//"sub": "24400320",
	//"aud": "s6BhdRkqt3",
	//"nonce": "n-0S6_WzA2Mj",
	//"exp": 1311281970,
	//"iat": 1311280970,
	//"auth_time": 1311280969,
	//"acr": "urn:mace:incommon:iap:silver"

	claims.RegisterIss("https://server.example.com")
	claims.RegisterSub("24400320")
	claims.RegisterExp(time.Now())
	claims.RegisterIat(time.Now())
	claims.IssuedAt()
	claims.Subject()
	claims.Expiration() // or claims.ExpirationTime()
	claims.IssuedAt()

	claims.Register("acr", "urn:mace:incommon:iap:silver")
	claims.Register("nonce", "a string value")
	claims.RegisterByTime("auth_time", time.Now())

	header := NewHeader()
	header.Register(HEADER_TYPE, "JWT")
	header.Register(HEADER_ALGORITHM, crypto.HS256)
	token := NewToken(claims, header, "abcdef")

	serializedToken, _ := token.Serialize()

	// Unmarshal JSON
	newToken, e := ParseToken(serializedToken, "abcdef")
	if e != nil {
		util.Debug(e)
	}

	c := newToken.Claims()
	newToken.Header()
	// Get Audience
	aud, ok := c.Audience()
	if !ok {

		// Fails
		t.Fail()
	}
	util.Debug(c)
	t.Logf("aud len(): %d", len(aud))
	t.Logf("aud Value: %s", aud)
	t.Logf("aud Type : %T", aud)
}

func TestSingleAudienceFix_AfterMarshal(t *testing.T) {
	// Create JWS claims
	// Create JWS claims
	claims := NewClaims()
	claims.RegisterAud("example.com", "api.example.com")
	header := NewHeader()
	header.Register(HEADER_TYPE, "JWT")
	header.Register(HEADER_ALGORITHM, "HS256")
	token := NewToken(claims, header, "abcdef")

	serializedToken, _ := token.Serialize()

	// Unmarshal JSON
	newToken, _ := ParseToken(serializedToken, "abcdef")
	c := newToken.Claims()

	// Get Audience
	aud, ok := c.Audience()
	if !ok {

		// Fails
		t.Fail()
	}

	t.Logf("aud len(): %d", len(aud))
	t.Logf("aud Value: %s", aud)
	t.Logf("aud Type : %T", aud)
}

func TestValidate(t *testing.T) {
	now := time.Date(2015, 1, 1, 0, 0, 0, 0, time.UTC)
	before, after := now.Add(-time.Minute), now.Add(time.Minute)
	leeway := 10 * time.Second

	exp := func(t time.Time) Claims {
		claims := NewClaims()
		claims.RegisterExp(t)
		return *claims
		//return Claims{ClaimData: map[string]interface{"exp": t.Unix()}}
	}
	nbf := func(t time.Time) Claims {
		claims := NewClaims()
		claims.RegisterNbf(t)
		return *claims

		//return jwt.Claims{"nbf": t.Unix()}
	}

	var tests = []struct {
		desc      string
		c         Claims
		now       time.Time
		expLeeway time.Duration
		nbfLeeway time.Duration
		err       error
	}{
		// test for nbf < now <= exp
		{desc: "exp == nil && nbf == nil", c: Claims{}, now: now, err: nil},

		{desc: "now > exp", now: now, c: exp(before), err: ErrorTokenIsExpired},
		{desc: "now = exp", now: now, c: exp(now), err: nil},
		{desc: "now < exp", now: now, c: exp(after), err: nil},

		{desc: "nbf < now", c: nbf(before), now: now, err: nil},
		{desc: "nbf = now", c: nbf(now), now: now, err: ErrorTokenNotYetValid},
		{desc: "nbf > now", c: nbf(after), now: now, err: ErrorTokenNotYetValid},

		// test for nbf-x < now <= exp+y
		{desc: "now < exp+x", now: now.Add(leeway - time.Second), expLeeway: leeway, c: exp(now), err: nil},
		{desc: "now = exp+x", now: now.Add(leeway), expLeeway: leeway, c: exp(now), err: nil},
		{desc: "now > exp+x", now: now.Add(leeway + time.Second), expLeeway: leeway, c: exp(now), err: ErrorTokenIsExpired},

		{desc: "nbf-x > now", c: nbf(now), nbfLeeway: leeway, now: now.Add(-leeway + time.Second), err: nil},
		{desc: "nbf-x = now", c: nbf(now), nbfLeeway: leeway, now: now.Add(-leeway), err: ErrorTokenNotYetValid},
		{desc: "nbf-x < now", c: nbf(now), nbfLeeway: leeway, now: now.Add(-leeway - time.Second), err: ErrorTokenNotYetValid},
	}

	for i, tt := range tests {
		if got, want := tt.c.Validate(tt.now, tt.expLeeway, tt.nbfLeeway), tt.err; got != want {
			t.Errorf("%d - %q: got %v want %v", i, tt.desc, got, want)
		}
	}
}

func TestGetAndSetTime(t *testing.T) {
	now := time.Now()
	nowUnix := now.Unix()
	c := NewClaims()
	c.Register("int", int(nowUnix))
	c.Register("int32", int32(nowUnix))
	c.Register("int64", int64(nowUnix))
	c.Register("uint", uint(nowUnix))
	c.Register("uint32", uint32(nowUnix))
	c.Register("uint64", uint64(nowUnix))
	c.Register("float64", float64(nowUnix))

	c.RegisterByTime("setTime", now)
	for k := range *c {
		v, _ := c.Find(k)
		v1, ok := util.LiteralToTime(v)
		if got, want := v1, time.Unix(nowUnix, 0); !ok || !got.Equal(want) {
			t.Errorf("%s: got %v want %v", k, got, want)
		}
	}
}

func TestTimeValuesThroughJSON(t *testing.T) {
	now := time.Unix(time.Now().Unix(), 0)

	c := NewClaims()
	c.RegisterIat(now)
	c.RegisterNbf(now)
	c.RegisterExp(now)

	h := NewJWTHeader()
	h.Register("alg", "HS256")
	// serialize to JWT
	tok := NewToken(c, h, "key")
	b, err := tok.Serialize()
	if err != nil {
		t.Fatal(err)
	}

	// parse the JWT again
	tok2, err := ParseToken(b, "key")
	if err != nil {
		t.Fatal(err)
	}
	c2 := tok2.Claims()

	iat, ok1 := c2.IssuedAt()
	nbf, ok2 := c2.NotBefore()
	exp, ok3 := c2.ExpirationTime()
	if !ok1 || !ok2 || !ok3 {
		t.Fatal("got false want true", ok1, ok2, ok3)
	}

	if got, want := iat, now; !got.Equal(want) {
		t.Errorf("%s: got %v want %v", "iat", got, want)
	}
	if got, want := nbf, now; !got.Equal(want) {
		t.Errorf("%s: got %v want %v", "nbf", got, want)
	}
	if got, want := exp, now; !got.Equal(want) {
		t.Errorf("%s: got %v want %v", "exp", got, want)
	}
}
