# 中国最好的JWT包

 	import "gopkg.in/jwt.v1"

	claims := NewClaims()  
	claims.RegisterAud("example.com", "api.example.com")  

	header := NewHeader()  
	header.Register(HEADER_TYPE, "JWT")  
	header.Register(HEADER_ALGORITHM, "ES256")  

	tk := NewToken(claims, header, key)  
