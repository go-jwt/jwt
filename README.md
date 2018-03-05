# 做中国最好的JWT包

# How to use it?
## 获取包
	go get -u gopkg.in/jwt.v1
## Example:
    //获取一个claims
    claims := NewClaims()
    //注册一个域名
	claims.RegisterAud("example.com", "api.example.com")

	/*
	"iss": "https://server.example.com",
	"sub": "24400320",
	"aud": "s6BhdRkqt3",
	"nonce": "n-0S6_WzA2Mj",
	"exp": 1311281970,
	"iat": 1311280970,
	"auth_time": 1311280969,
	"acr": "urn:mace:incommon:iap:silver"
	*/
    	//上面的数据串可以通过如下方式注册
	claims.RegisterIss("https://server.example.com")
	claims.RegisterSub("24400320")
	claims.RegisterExp(time.Now())
	claims.RegisterIat(time.Now())
	
	//获取数据串
	claims.IssuedAt()
	claims.Subject()
	claims.Expiration() // or claims.ExpirationTime()
	claims.IssuedAt()	
	
	//自定义一个string的acr值
	claims.Register("acr","urn:mace:incommon:iap:silver")
	claims.Register("nonce","a string value")
	//传入一个time类型
	claims.RegisterByTime("auth_time",time.Now())


	//创建一个header
	header := NewHeader() // or NewJWTHeader
	header.Register(HEADER_TYPE, "JWT")
	//指定压缩方式
	header.Register(HEADER_ALGORITHM, "HS256")
	//或者
	header := DefaultHeader()
	
	//使用claims，header，key 来创建token
	token := NewToken(claims, header, "abcdef")

    	//使用序列化token用于传输
	serializedToken, _ := token.Serialize()



    	//当接受到一串序列化token时:
	//通过key和序列化token，反序列化得到token
	newToken, _ := ParseToken(serializedToken, "abcdef")

    	//获取claims
	newToken.Claims()
	//获取header
	newToken.Header()

	//验证claims
	claims.Validate(newToken)
 
