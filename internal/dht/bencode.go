// SPDX-License-Identifier: MPL-2.0

package dht

import (
	"bytes"
	"errors"
	"fmt"
	"sort"
	"strconv"
)

// A minimal bencode (BEP 3) for KRPC messages: byte strings, integers,
// lists and dictionaries with string keys.

var errBencode = errors.New("dht: bad bencode")

func encode(buf *bytes.Buffer, v any) error {
	switch x := v.(type) {
	case string:
		buf.WriteString(strconv.Itoa(len(x)) + ":" + x)
	case []byte:
		buf.WriteString(strconv.Itoa(len(x)) + ":")
		buf.Write(x)
	case int:
		buf.WriteString("i" + strconv.Itoa(x) + "e")
	case int64:
		buf.WriteString("i" + strconv.FormatInt(x, 10) + "e")
	case []any:
		buf.WriteByte('l')
		for _, e := range x {
			if err := encode(buf, e); err != nil {
				return err
			}
		}
		buf.WriteByte('e')
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf.WriteByte('d')
		for _, k := range keys {
			encode(buf, k)
			if err := encode(buf, x[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('e')
	default:
		return fmt.Errorf("dht: cannot bencode %T", v)
	}
	return nil
}

// Encode bencodes a value.
func Encode(v any) ([]byte, error) {
	var b bytes.Buffer
	err := encode(&b, v)
	return b.Bytes(), err
}

// Decode parses one bencoded value: strings become string, integers
// int64, lists []any, dictionaries map[string]any.
func Decode(b []byte) (any, error) {
	v, rest, err := decode(b, 0)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return nil, errBencode
	}
	return v, nil
}

func decode(b []byte, depth int) (any, []byte, error) {
	if len(b) == 0 || depth > 32 {
		return nil, nil, errBencode
	}
	switch c := b[0]; {
	case c == 'i':
		end := bytes.IndexByte(b, 'e')
		if end < 2 {
			return nil, nil, errBencode
		}
		n, err := strconv.ParseInt(string(b[1:end]), 10, 64)
		if err != nil {
			return nil, nil, errBencode
		}
		return n, b[end+1:], nil
	case c == 'l':
		var out []any
		b = b[1:]
		for len(b) > 0 && b[0] != 'e' {
			v, rest, err := decode(b, depth+1)
			if err != nil {
				return nil, nil, err
			}
			out = append(out, v)
			b = rest
		}
		if len(b) == 0 {
			return nil, nil, errBencode
		}
		return out, b[1:], nil
	case c == 'd':
		out := map[string]any{}
		b = b[1:]
		for len(b) > 0 && b[0] != 'e' {
			k, rest, err := decode(b, depth+1)
			if err != nil {
				return nil, nil, err
			}
			key, ok := k.(string)
			if !ok {
				return nil, nil, errBencode
			}
			v, rest, err := decode(rest, depth+1)
			if err != nil {
				return nil, nil, err
			}
			out[key] = v
			b = rest
		}
		if len(b) == 0 {
			return nil, nil, errBencode
		}
		return out, b[1:], nil
	case c >= '0' && c <= '9':
		colon := bytes.IndexByte(b, ':')
		if colon < 1 {
			return nil, nil, errBencode
		}
		n, err := strconv.Atoi(string(b[:colon]))
		if err != nil || n < 0 || colon+1+n > len(b) {
			return nil, nil, errBencode
		}
		return string(b[colon+1 : colon+1+n]), b[colon+1+n:], nil
	}
	return nil, nil, errBencode
}
