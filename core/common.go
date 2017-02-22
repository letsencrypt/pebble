package core

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
)

// RandomString and NewToken come from Boulder core/util.go
// RandomString returns a randomly generated string of the requested length.
func RandomString(byteLength int) string {
	b := make([]byte, byteLength)
	_, err := io.ReadFull(rand.Reader, b)
	if err != nil {
		panic(fmt.Sprintf("Error reading random bytes: %s", err))
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// NewToken produces a random string for Challenges, etc.
func NewToken() string {
	return RandomString(32)
}
