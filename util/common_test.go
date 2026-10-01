package util

import (
	"errors"
	"io"
	"log"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

type closingBody struct {
	io.Reader
	err    error
	closes int
}

func (b *closingBody) Close() error {
	b.closes++
	return b.err
}

func TestSafeClose(t *testing.T) {
	var logs strings.Builder
	previous := log.Writer()
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(previous) })

	SafeClose(nil)
	for _, err := range []error{nil, errors.New("confidential-close-canary")} {
		body := &closingBody{Reader: strings.NewReader(""), err: err}
		SafeClose(&http.Response{Body: body})
		assert.Equal(t, 1, body.closes)
	}
	assert.Empty(t, logs.String(), "close errors must not be logged")
}
