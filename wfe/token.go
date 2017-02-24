package wfe

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
)

// randomString and newToken come from Boulder core/util.go
// randomString returns a randomly generated string of the requested length.
func randomString(byteLength int) string {
	b := make([]byte, byteLength)
	_, err := io.ReadFull(rand.Reader, b)
	if err != nil {
		panic(fmt.Sprintf("Error reading random bytes: %s", err))
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// newToken produces a random string for Challenges, etc.
func newToken() string {
	return randomString(32)
}
