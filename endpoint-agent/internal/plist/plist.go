// Package plist decodes XML property lists (Apple's Info.plist / preference
// format) into plain Go values: map[string]any, []any, string, int64, float64,
// bool, time.Time and []byte. Binary plists must be converted first
// (`plutil -convert xml1 -o - file`), which the macOS collector does.
package plist

import (
	"bytes"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

// ErrBinary is returned for binary ("bplist00") property lists.
var ErrBinary = errors.New("binary plist")

// MaxDepth bounds nesting to keep hostile files from exhausting the stack.
const MaxDepth = 64

// Decode parses an XML plist and returns its root value.
func Decode(data []byte) (any, error) {
	if bytes.HasPrefix(data, []byte("bplist")) {
		return nil, ErrBinary
	}
	dec := xml.NewDecoder(bytes.NewReader(data))
	dec.Strict = false
	for {
		tok, err := dec.Token()
		if err != nil {
			if err == io.EOF {
				return nil, errors.New("plist: no root element")
			}
			return nil, err
		}
		if se, ok := tok.(xml.StartElement); ok {
			if se.Name.Local == "plist" {
				continue
			}
			return decodeValue(dec, se, 0)
		}
	}
}

// DecodeDict decodes a plist whose root is a dictionary.
func DecodeDict(data []byte) (map[string]any, error) {
	v, err := Decode(data)
	if err != nil {
		return nil, err
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("plist: root is %T, not a dict", v)
	}
	return m, nil
}

func text(dec *xml.Decoder, se xml.StartElement) (string, error) {
	var s string
	if err := dec.DecodeElement(&s, &se); err != nil {
		return "", err
	}
	return s, nil
}

func decodeValue(dec *xml.Decoder, se xml.StartElement, depth int) (any, error) {
	if depth > MaxDepth {
		return nil, errors.New("plist: nesting too deep")
	}
	switch se.Name.Local {
	case "dict":
		m := map[string]any{}
		var key *string
		for {
			tok, err := dec.Token()
			if err != nil {
				return nil, err
			}
			switch t := tok.(type) {
			case xml.StartElement:
				if t.Name.Local == "key" {
					k, err := text(dec, t)
					if err != nil {
						return nil, err
					}
					key = &k
					continue
				}
				v, err := decodeValue(dec, t, depth+1)
				if err != nil {
					return nil, err
				}
				if key != nil {
					m[*key] = v
					key = nil
				}
			case xml.EndElement:
				return m, nil
			}
		}
	case "array":
		arr := []any{}
		for {
			tok, err := dec.Token()
			if err != nil {
				return nil, err
			}
			switch t := tok.(type) {
			case xml.StartElement:
				v, err := decodeValue(dec, t, depth+1)
				if err != nil {
					return nil, err
				}
				arr = append(arr, v)
			case xml.EndElement:
				return arr, nil
			}
		}
	case "string":
		return text(dec, se)
	case "integer":
		s, err := text(dec, se)
		if err != nil {
			return nil, err
		}
		return strconv.ParseInt(strings.TrimSpace(s), 0, 64)
	case "real":
		s, err := text(dec, se)
		if err != nil {
			return nil, err
		}
		return strconv.ParseFloat(strings.TrimSpace(s), 64)
	case "true", "false":
		if err := dec.Skip(); err != nil {
			return nil, err
		}
		return se.Name.Local == "true", nil
	case "date":
		s, err := text(dec, se)
		if err != nil {
			return nil, err
		}
		return time.Parse(time.RFC3339, strings.TrimSpace(s))
	case "data":
		s, err := text(dec, se)
		if err != nil {
			return nil, err
		}
		return base64.StdEncoding.DecodeString(strings.Join(strings.Fields(s), ""))
	default:
		if err := dec.Skip(); err != nil {
			return nil, err
		}
		return nil, nil
	}
}

// String returns m[key] if it is a string.
func String(m map[string]any, key string) string {
	s, _ := m[key].(string)
	return s
}

// Int returns m[key] if it is an integer.
func Int(m map[string]any, key string) (int64, bool) {
	v, ok := m[key].(int64)
	return v, ok
}

// Time returns m[key] if it is a date.
func Time(m map[string]any, key string) (time.Time, bool) {
	v, ok := m[key].(time.Time)
	return v, ok
}
