package wfe

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/letsencrypt/pebble/v2/acme"
)

func TestNewAccountRejectsUnsupportedSignatureAlgorithm(t *testing.T) {
	t.Parallel()

	wfe := &WebFrontEndImpl{
		log:   log.New(io.Discard, "", 0),
		nonce: newNonceMap(),
	}
	protected := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"unsupported"}`))
	body := `{"protected":"` + protected + `","payload":"","signature":"AA"}`
	req := httptest.NewRequest(http.MethodPost, newAccountPath, strings.NewReader(body))
	req.Header.Set("Content-Type", expectedJWSContentType)
	req.Header.Set("User-Agent", "pebble-test")
	recorder := httptest.NewRecorder()

	wfe.Handler().ServeHTTP(recorder, req)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("response status = %d, want %d", recorder.Code, http.StatusBadRequest)
	}
	var problem acme.ProblemDetails
	if err := json.Unmarshal(recorder.Body.Bytes(), &problem); err != nil {
		t.Fatalf("unmarshaling problem response: %v", err)
	}
	if problem.Type != "urn:ietf:params:acme:error:badSignatureAlgorithm" {
		t.Errorf("problem type = %q, want badSignatureAlgorithm (detail: %q)",
			problem.Type, problem.Detail)
	}
	wantAlgorithms := []string{
		"ES256", "ES384", "ES512", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87", "RS256",
	}
	if !reflect.DeepEqual(problem.Algorithms, wantAlgorithms) {
		t.Errorf("algorithms = %q, want %q", problem.Algorithms, wantAlgorithms)
	}
}
