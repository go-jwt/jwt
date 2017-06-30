package util

import (
	"reflect"

	"github.com/golang/dep/vendor/github.com/pkg/errors"
)

var (
	ErrorNotSameType      = errors.New("it is not the same type")
	ErrorNotSameSize      = errors.New("it is not the same size")
	ErrorValidationFailed = errors.New("validation failed")
)

func ArrayCompare(v1, v2 interface{}) error {
	var e error
	if reflect.TypeOf(v1) != reflect.TypeOf(v2) {
		return ErrorNotSameType
	}

	switch v1.(type) {
	case []string:
		e = CompareStringArray(v1.([]string), v2.([]string))
	default:
		e = ErrorValidationFailed
	}
	return e
}

func CompareStringArray(v1, v2 []string) error {
	vlen := len(v1)
	if vlen != len(v2) {
		return ErrorNotSameSize
	}
	count := 0
	for _, v1t := range v1 {
		for _, v2t := range v2 {
			if v1t == v2t {
				count++
				continue
			}
		}
	}
	if count != vlen {
		return ErrorValidationFailed
	}
	return nil
}
