package crypto

const (
	NONE = "none" //plaintext (unprotected) without signature / encryption

	HS256 = "HS256" //HMAC using SHA-256 hash
	HS384 = "HS384" //HMAC using SHA-384 hash
	HS512 = "HS512" //HMAC using SHA-512 hash
	RS256 = "RS256" //RSASSA-PKCS-v1_5 using SHA-256 hash
	RS384 = "RS384" //RSASSA-PKCS-v1_5 using SHA-384 hash
	RS512 = "RS512" //RSASSA-PKCS-v1_5 using SHA-512 hash
	PS256 = "PS256" //RSASSA-PSS using SHA-256 hash
	PS384 = "PS384" //RSASSA-PSS using SHA-384 hash
	PS512 = "PS512" //RSASSA-PSS using SHA-512 hash
	ES256 = "ES256" //ECDSA using P-256 curve and SHA-256 hash
	ES384 = "ES384" //ECDSA using P-384 curve and SHA-384 hash
	ES512 = "ES512" //ECDSA using P-521 curve and SHA-512 hash

	A128CBC_HS256 = "A128CBC-HS256" //AES in CBC mode with PKCS #5 (NIST.800-38A) padding with HMAC using 256 bit key
	A192CBC_HS384 = "A192CBC-HS384" //AES in CBC mode with PKCS #5 (NIST.800-38A) padding with HMAC using 384 bit key
	A256CBC_HS512 = "A256CBC-HS512" //AES in CBC mode with PKCS #5 (NIST.800-38A) padding with HMAC using 512 bit key
	A128GCM       = "A128GCM"       //AES in GCM mode with 128 bit key
	A192GCM       = "A192GCM"       //AES in GCM mode with 192 bit key
	A256GCM       = "A256GCM"       //AES in GCM mode with 256 bit key

	DIR                = "dir"                //Direct use of pre-shared symmetric key
	RSA1_5             = "RSA1_5"             //RSAES with PKCS #1 v1.5 padding, RFC 3447
	RSA_OAEP           = "RSA-OAEP"           //RSAES using Optimal Assymetric Encryption Padding, RFC 3447
	RSA_OAEP_256       = "RSA-OAEP-256"       //RSAES using Optimal Assymetric Encryption Padding with SHA-256, RFC 3447
	A128KW             = "A128KW"             //AES Key Wrap Algorithm using 128 bit keys, RFC 3394
	A192KW             = "A192KW"             //AES Key Wrap Algorithm using 192 bit keys, RFC 3394
	A256KW             = "A256KW"             //AES Key Wrap Algorithm using 256 bit keys, RFC 3394
	A128GCMKW          = "A128GCMKW"          //AES GCM Key Wrap Algorithm using 128 bit keys
	A192GCMKW          = "A192GCMKW"          //AES GCM Key Wrap Algorithm using 192 bit keys
	A256GCMKW          = "A256GCMKW"          //AES GCM Key Wrap Algorithm using 256 bit keys
	PBES2_HS256_A128KW = "PBES2-HS256+A128KW" //Password Based Encryption using PBES2 schemes with HMAC-SHA and AES Key Wrap using 128 bit key
	PBES2_HS384_A192KW = "PBES2-HS384+A192KW" //Password Based Encryption using PBES2 schemes with HMAC-SHA and AES Key Wrap using 192 bit key
	PBES2_HS512_A256KW = "PBES2-HS512+A256KW" //Password Based Encryption using PBES2 schemes with HMAC-SHA and AES Key Wrap using 256 bit key
	ECDH_ES            = "ECDH-ES"            //Elliptic Curve Diffie Hellman key agreement
	ECDH_ES_A128KW     = "ECDH-ES+A128KW"     //Elliptic Curve Diffie Hellman key agreement with AES Key Wrap using 128 bit key
	ECDH_ES_A192KW     = "ECDH-ES+A192KW"     //Elliptic Curve Diffie Hellman key agreement with AES Key Wrap using 192 bit key
	ECDH_ES_A256KW     = "ECDH-ES+A256KW"     //Elliptic Curve Diffie Hellman key agreement with AES Key Wrap using 256 bit key

	DEF = "DEF" //DEFLATE compression, RFC 1951
)
