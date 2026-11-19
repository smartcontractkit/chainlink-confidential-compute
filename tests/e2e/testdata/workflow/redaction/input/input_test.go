package input

import "testing"

func TestRequestURL(t *testing.T) {
	for _, tt := range []struct {
		name string
		url  string
	}{
		{"redirect", "https://httpbingo.org/redirect-to?url=https%3A%2F%2Fexample.com%2Fcc-redaction-smoke%3Ftoken%3Dcc-redaction-smoke"},
		{"certificate", "https://wrong.host.badssl.com/cc-redaction-smoke?token=cc-redaction-smoke"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			name, url, err := RequestURL([]byte(`{"case":"` + tt.name + `"}`))
			if err != nil || name != tt.name || url != tt.url {
				t.Fatalf("RequestURL = (%q, %q, %v), want (%q, %q, nil)", name, url, err, tt.name, tt.url)
			}
		})
	}
}

func TestRequestURLRejectsInvalidInput(t *testing.T) {
	for _, raw := range []string{
		``, `null`, `[]`, `{}`, `{"case":null}`, `{"case":42}`,
		`{"case":"fake-secret"}`, `{"case":"redirect"} {}`, `{"case":`,
		`{"case":"redirect","url":"https://fake-secret.example"}`,
		`{"case":"certificate","headers":{}}`,
	} {
		t.Run(raw, func(t *testing.T) {
			name, url, err := RequestURL([]byte(raw))
			if name != "" || url != "" || err == nil || err.Error() != "input must contain only case: redirect or certificate" {
				t.Fatalf("RequestURL = (%q, %q, %v), want empty outputs and fixed validation error", name, url, err)
			}
		})
	}
}
