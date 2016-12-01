package wfe

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"sync"
)

/*
 * Boulder uses 32 byte nonces.  We specifically choose to use 16 byte nonces
 * here to A) be different than Boulder and force clients to not rely on
 * Boulder-specific details B) to match the example text from draft-04 that
 * describes "a random 128-bit value for each response"
 */
const nonceLen = 16

/*
 * Note: We place no upper bound on the number of nonces we issue. We obtain
 * a lock for both issuing nonces and checking them. This is *not* a performant
 * or safe strategy for a production server. Consider the NonceServer
 * approach[0] used by Boulder if you are looking for a more robust nonce
 * implementation for an ACME server.
 *
 * [0] - https://github.com/letsencrypt/boulder/blob/c8f1fb3e2fade026aad76f23eafa137482d89bf5/nonce/nonce.go
 */
type nonceMap struct {
	sync.Mutex
	nonces map[string]struct{}
}

func newNonceMap() *nonceMap {
	return &nonceMap{nonces: make(map[string]struct{})}
}

func (n *nonceMap) createNonce() string {
	n.Lock()
	defer n.Unlock()

	// Read `nonceLen` random bytes from rand.Reader
	b := make([]byte, nonceLen)
	_, err := io.ReadFull(rand.Reader, b)
	if err != nil {
		panic(fmt.Sprintf("Error reading random bytes: %s", err))
	}

	// Encode the bytes to base64 URL encoding
	nonce := base64.RawURLEncoding.EncodeToString(b)
	// Record the nonce, and give it back to the caller
	n.nonces[nonce] = struct{}{}
	return nonce
}

func (n *nonceMap) validNonce(nonce string) bool {
	n.Lock()
	defer n.Unlock()

	// If the nonce is one we generated its valid
	if _, present := n.nonces[nonce]; present {
		// Strike the nonce after it has been validated
		// It can only be used once!
		delete(n.nonces, nonce)
		return true
	}

	return false
}
