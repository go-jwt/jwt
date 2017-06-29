package util

import (
	"reflect"
)

func LiteralToBytes(v interface{}) ([]byte, bool) {
	var keyBytes []byte
	switch v.(type) {
	case []byte:
		keyBytes = v.([]byte)
	case string:
		keyBytes = []byte(v.(string))
	default:
		Debug("unknow sign key type", reflect.TypeOf(v))
		return []byte(""), false
	}
	return keyBytes, true
}
