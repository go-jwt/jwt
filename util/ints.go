package util

import "time"

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
