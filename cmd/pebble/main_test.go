package main

import (
	"io"
	"log"
	"os"
	"testing"
	"time"

	"github.com/letsencrypt/pebble/v2/ca"
)

func intPtr(i int) *int { return &i }

func TestLoadCRLConfig(t *testing.T) {
	envVars := []string{
		"PEBBLE_CRL_LISTEN_ADDRESS",
		"PEBBLE_CRL_BASE_URL",
		"PEBBLE_CRL_MAX_DELAY",
		"PEBBLE_CRL_VALIDITY",
	}
	const (
		listen = "0.0.0.0:4003"
		base   = "http://localhost:4003/"
	)
	defaultValidity := defaultCRLValidity * time.Second

	testCases := []struct {
		name       string
		listen     string
		base       string
		maxDelay   *int
		validity   int
		env        map[string]string
		want       *ca.CRLConfig
		wantListen string
		wantErr    bool
	}{
		{
			name: "disabled by default",
		},
		{
			name:       "enabled with defaults",
			listen:     listen,
			base:       base,
			want:       &ca.CRLConfig{BaseURL: base, MaxDelay: defaultCRLMaxDelay, Validity: defaultValidity},
			wantListen: listen,
		},
		{
			name:       "enabled by env only",
			env:        map[string]string{"PEBBLE_CRL_LISTEN_ADDRESS": listen, "PEBBLE_CRL_BASE_URL": base},
			want:       &ca.CRLConfig{BaseURL: base, MaxDelay: defaultCRLMaxDelay, Validity: defaultValidity},
			wantListen: listen,
		},
		{
			name:     "env overrides config",
			listen:   "127.0.0.1:1",
			base:     "http://example.com/",
			maxDelay: intPtr(7),
			validity: 3600,
			env: map[string]string{
				"PEBBLE_CRL_LISTEN_ADDRESS": listen,
				"PEBBLE_CRL_BASE_URL":       base,
				"PEBBLE_CRL_MAX_DELAY":      "0",
				"PEBBLE_CRL_VALIDITY":       "7200",
			},
			want:       &ca.CRLConfig{BaseURL: base, MaxDelay: 0, Validity: 2 * time.Hour},
			wantListen: listen,
		},
		{
			name:       "empty env strings don't disable CRLs",
			listen:     listen,
			base:       base,
			env:        map[string]string{"PEBBLE_CRL_LISTEN_ADDRESS": "", "PEBBLE_CRL_BASE_URL": ""},
			want:       &ca.CRLConfig{BaseURL: base, MaxDelay: defaultCRLMaxDelay, Validity: defaultValidity},
			wantListen: listen,
		},
		{
			name:       "non-integer env values are ignored",
			listen:     listen,
			base:       base,
			maxDelay:   intPtr(3),
			validity:   3600,
			env:        map[string]string{"PEBBLE_CRL_MAX_DELAY": "soon", "PEBBLE_CRL_VALIDITY": "long"},
			want:       &ca.CRLConfig{BaseURL: base, MaxDelay: 3, Validity: time.Hour},
			wantListen: listen,
		},
		{
			name:    "only listen address",
			listen:  listen,
			wantErr: true,
		},
		{
			name:    "only base URL",
			base:    base,
			wantErr: true,
		},
		{
			name:    "only base URL from env",
			env:     map[string]string{"PEBBLE_CRL_BASE_URL": base},
			wantErr: true,
		},
		{
			name:    "https base URL",
			listen:  listen,
			base:    "https://localhost:4003/",
			wantErr: true,
		},
		{
			name:    "relative base URL",
			listen:  listen,
			base:    "/crls/",
			wantErr: true,
		},
		{
			name:       "trailing slash added",
			listen:     listen,
			base:       "http://localhost:4003/crls",
			want:       &ca.CRLConfig{BaseURL: "http://localhost:4003/crls/", MaxDelay: defaultCRLMaxDelay, Validity: defaultValidity},
			wantListen: listen,
		},
		{
			name:       "validity over 10 days is clamped",
			listen:     listen,
			base:       base,
			validity:   maxCRLValidity + 1,
			want:       &ca.CRLConfig{BaseURL: base, MaxDelay: defaultCRLMaxDelay, Validity: maxCRLValidity * time.Second},
			wantListen: listen,
		},
		{
			name:       "validity 0 from env uses default",
			listen:     listen,
			base:       base,
			validity:   3600,
			env:        map[string]string{"PEBBLE_CRL_VALIDITY": "0"},
			want:       &ca.CRLConfig{BaseURL: base, MaxDelay: defaultCRLMaxDelay, Validity: defaultValidity},
			wantListen: listen,
		},
		{
			name:     "negative validity",
			listen:   listen,
			base:     base,
			validity: -1,
			wantErr:  true,
		},
		{
			name:    "negative validity from env",
			listen:  listen,
			base:    base,
			env:     map[string]string{"PEBBLE_CRL_VALIDITY": "-1"},
			wantErr: true,
		},
		{
			name:     "negative max delay",
			listen:   listen,
			base:     base,
			maxDelay: intPtr(-1),
			wantErr:  true,
		},
		{
			name:    "negative max delay from env",
			listen:  listen,
			base:    base,
			env:     map[string]string{"PEBBLE_CRL_MAX_DELAY": "-5"},
			wantErr: true,
		},
		{
			name: "negative values ignored with CRLs disabled",
			env:  map[string]string{"PEBBLE_CRL_MAX_DELAY": "-1", "PEBBLE_CRL_VALIDITY": "-1"},
		},
		{
			name:       "explicit zero max delay",
			listen:     listen,
			base:       base,
			maxDelay:   intPtr(0),
			want:       &ca.CRLConfig{BaseURL: base, MaxDelay: 0, Validity: defaultValidity},
			wantListen: listen,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			for _, name := range envVars {
				// t.Setenv registers the original value for restoring after
				// the test, even if the variable is then unset.
				t.Setenv(name, "")
				if val, ok := tc.env[name]; ok {
					t.Setenv(name, val)
				} else {
					_ = os.Unsetenv(name)
				}
			}

			var c config
			c.Pebble.CRLListenAddress = tc.listen
			c.Pebble.CRLBaseURL = tc.base
			c.Pebble.CRLMaxDelay = tc.maxDelay
			c.Pebble.CRLValidity = tc.validity

			got, err := loadCRLConfig(&c, log.New(io.Discard, "", 0))
			if tc.wantErr {
				if err == nil {
					t.Fatalf("loadCRLConfig() = %+v, want an error", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("loadCRLConfig() returned error: %s", err)
			}

			switch {
			case tc.want == nil && got != nil:
				t.Errorf("loadCRLConfig() = %+v, want nil", got)
			case tc.want != nil && got == nil:
				t.Errorf("loadCRLConfig() = nil, want %+v", tc.want)
			case tc.want != nil && *got != *tc.want:
				t.Errorf("loadCRLConfig() = %+v, want %+v", got, tc.want)
			}
			if tc.want != nil && c.Pebble.CRLListenAddress != tc.wantListen {
				t.Errorf("effective listen address = %q, want %q", c.Pebble.CRLListenAddress, tc.wantListen)
			}
		})
	}
}
