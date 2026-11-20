package input

import (
	"encoding/json"
	"errors"
)

const Marker = "cc-redaction-smoke"

func RequestURL(raw []byte) (caseName, url string, err error) {
	var input map[string]string
	if json.Unmarshal(raw, &input) == nil && len(input) == 1 {
		switch input["case"] {
		case "redirect":
			return "redirect", "https://httpbingo.org/redirect-to?url=https%3A%2F%2Fexample.com%2F" + Marker + "%3Ftoken%3D" + Marker, nil
		case "certificate":
			return "certificate", "https://wrong.host.badssl.com/" + Marker + "?token=" + Marker, nil
		}
	}
	return "", "", errors.New("input must contain only case: redirect or certificate")
}
