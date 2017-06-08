package util

func LiteralToStringArray(v interface{}) []string {
	var r []string

	switch v.(type) {
	case []string:
		r = v.([]string)
	case string:
		r = []string{v.(string)}
	case []interface{}:
		for _, v := range v.([]interface{}) {
			if v1, b := LiteralToString(v); b {
				r = append(r, v1)
			}
		}
	case interface{}:
		if v1, b := LiteralToString(v); b {
			r = append(r, v1)
		}
	default:
		return nil
	}

	return r
}

func LiteralToString(v interface{}) (string, bool) {
	if v, b := v.(string); b {
		return v, true
	}
	if v, b := v.([]byte); b {
		return string(v), true
	}
	return "", false
}
