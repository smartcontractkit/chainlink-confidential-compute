package util

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
)

type EchoResponse struct {
	Args    map[string]string `json:"args"`
	Data    interface{}       `json:"data,omitempty"`
	Files   map[string]string `json:"files"` // unimplemented
	Form    map[string]string `json:"form"`
	Headers map[string]string `json:"headers"`
	JSON    interface{}       `json:"json,omitempty"`
	URL     string            `json:"url"`
}

func echoHandler(w http.ResponseWriter, r *http.Request) {
	args := make(map[string]string)
	for key, values := range r.URL.Query() {
		if len(values) > 0 {
			args[key] = strings.Join(values, ",")
		}
	}

	headers := make(map[string]string)
	for key, values := range r.Header {
		if len(values) > 0 {
			headers[strings.ToLower(key)] = strings.Join(values, ",")
		}
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Error reading body", http.StatusInternalServerError)
		return
	}
	defer func() {
		err := r.Body.Close()
		if err != nil {
			log.Printf("Error closing body: %v", err)
		}
	}()

	// Construct full URL including scheme, host, and path
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	fullURL := fmt.Sprintf("%s://%s%s", scheme, r.Host, r.RequestURI)

	response := EchoResponse{
		Args:    args,
		Files:   make(map[string]string),
		Form:    make(map[string]string),
		Headers: headers,
		URL:     fullURL,
	}

	contentType := strings.ToLower(r.Header.Get("Content-Type"))
	if len(body) > 0 {
		switch {
		case strings.Contains(contentType, "application/json"):
			var jsonData interface{}
			if err := json.Unmarshal(body, &jsonData); err == nil {
				response.JSON = jsonData
				response.Data = jsonData
			} else {
				response.Data = string(body)
			}
		case strings.Contains(contentType, "application/x-www-form-urlencoded"):
			values, err := url.ParseQuery(string(body))
			if err == nil {
				for key, vals := range values {
					if len(vals) > 0 {
						response.Form[key] = strings.Join(vals, ",")
					}
				}
			} else {
				response.Data = string(body)
			}
		default:
			response.Data = string(body)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("Error encoding response: %v", err)
	}
}

func StartEchoServer(port int) string {
	addr := fmt.Sprintf("0.0.0.0:%d", port)
	http.HandleFunc("/", echoHandler)

	url := fmt.Sprintf("http://localhost:%d/", port)
	log.Printf("Starting echo server at %s", url)

	go func() {
		if err := http.ListenAndServe(addr, nil); err != nil {
			log.Fatalf("Server failed to start: %v", err)
		}
	}()
	return url
}
