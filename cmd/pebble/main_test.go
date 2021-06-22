package main

import (
	"bytes"
	"log"
	"strings"
	"testing"
)

func newLoggerAndBuffer(testName string) (*log.Logger, *bytes.Buffer) {
	buf := &bytes.Buffer{}
	return log.New(buf, testName+" ", 0), buf
}

func validateLogs(t *testing.T, logs string, expected []string) {
	t.Helper()

	if len(expected) == 0 && len(logs) != 0 {
		t.Errorf("got logs when none were expected: %s", logs)
	} else if strings.Count(logs, "\n") != len(expected) {
		t.Errorf("unexpected log count actual=%d, expected=%d", strings.Count(logs, "\n"), len(expected))
	}

	for _, e := range expected {
		if !strings.Contains(logs, e) {
			t.Errorf("expected log message [%s] not present", e)
		}
	}
}

func TestGetEnvSleepTime(t *testing.T) {
	// Summary from https://github.com/letsencrypt/pebble/pull/347#issuecomment-861634804:
	//
	// a. PEBBLE_VA_* missing, PEBBLE_SLEEPTIME missing, 5s delay on both
	// b. PEBBLE_VA_* present, PEBBLE_SLEEPTIME missing, VA delay (possibly 0 if NOSLEEP) on both, emit a deprecated message on startup
	// c. PEBBLE_VA_* missing, PEBBLE_SLEEPTIME present, specified delay on both
	// d. PEBBLE_VA_* present, PEBBLE_SLEEPTIME present, use PEBBLE_SLEEPTIME, emit a warning message on startup that both are present and one is deprecated.
	//
	// Invalid or negative integers are treated as missing.
	//
	// This expands to:
	// 1. PEBBLE_SLEEPTIME invalid, PEBBLE_VA_NOSLEEP clear, PEBBLE_VA_SLEEPTIME invalid - a
	// 2. PEBBLE_SLEEPTIME   valid, PEBBLE_VA_NOSLEEP clear, PEBBLE_VA_SLEEPTIME invalid - c
	// 3. PEBBLE_SLEEPTIME invalid, PEBBLE_VA_NOSLEEP clear, PEBBLE_VA_SLEEPTIME   valid - b (deprecated)
	// 4. PEBBLE_SLEEPTIME   valid, PEBBLE_VA_NOSLEEP clear, PEBBLE_VA_SLEEPTIME   valid - d (deprecated, conflict)
	// 5. PEBBLE_SLEEPTIME invalid, PEBBLE_VA_NOSLEEP   set, PEBBLE_VA_SLEEPTIME invalid - b (deprecated)
	// 6. PEBBLE_SLEEPTIME   valid, PEBBLE_VA_NOSLEEP   set, PEBBLE_VA_SLEEPTIME invalid - d (deprecated, conflict)
	// 7. PEBBLE_SLEEPTIME invalid, PEBBLE_VA_NOSLEEP   set, PEBBLE_VA_SLEEPTIME   valid - b (deprecated, conflict)
	// 8. PEBBLE_SLEEPTIME   valid, PEBBLE_VA_NOSLEEP   set, PEBBLE_VA_SLEEPTIME   valid - d (deprecated, conflict)
	t.Parallel()

	const (
		ignVaSleep     = "ignoring PEBBLE_VA_SLEEPTIME"
		ignVaNoSleep   = "ignoring PEBBLE_VA_NOSLEEP"
		ignVaBoth      = "ignoring PEBBLE_VA_NOSLEEP and PEBBLE_VA_SLEEPTIME"
		depVaSleep     = "PEBBLE_VA_SLEEPTIME is deprecated"
		depVaNoSleep   = "PEBBLE_VA_NOSLEEP is deprecated"
		parseSleep     = "parse PEBBLE_SLEEPTIME"
		parseVaSleep   = "parse PEBBLE_VA_SLEEPTIME"
		parseVaNoSleep = "parse PEBBLE_VA_NOSLEEP"
	)

	tests := []struct {
		name           string
		envSleepTime   string
		envVaNoSleep   string
		envVaSleepTime string
		expected       int
		expectedLogs   []string
	}{
		// happy paths
		{"defaults", "", "", "", defaultSleepTime, nil},                                            // 1
		{"sleep", "3", "", "", 3, nil},                                                             // 2
		{"vasleep", "", "", "3", 3, []string{depVaSleep}},                                          // 3
		{"sleep+vasleep", "3", "", "6", 3, []string{depVaSleep, ignVaSleep}},                       // 4
		{"nosleep", "", "1", "", 0, []string{depVaNoSleep}},                                        // 5
		{"sleep+nosleep", "3", "1", "", 3, []string{depVaNoSleep, ignVaNoSleep}},                   // 6
		{"nosleep+vasleep", "", "1", "3", 0, []string{depVaSleep, depVaNoSleep, ignVaSleep}},       // 7
		{"sleep+vasleep+nosleep", "3", "1", "6", 3, []string{depVaSleep, depVaNoSleep, ignVaBoth}}, // 8

		// parse failures
		{"sleep-inv", "f", "", "", defaultSleepTime, []string{parseSleep}},
		{"sleep-inv+vasleep+nosleep", "f", "1", "6", 0, []string{parseSleep, depVaSleep, depVaNoSleep, ignVaSleep}},
		{"vasleep-inv", "", "", "f", defaultSleepTime, []string{depVaSleep, parseVaSleep}},
		{"sleep+vasleep-inv+nosleep", "", "1", "f", 0, []string{depVaSleep, parseVaSleep, depVaNoSleep}},
		{"nosleep-inv", "", "f", "", defaultSleepTime, []string{depVaNoSleep, parseVaNoSleep}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			logger, logBuffer := newLoggerAndBuffer(test.name)
			if actual := getEnvSleepTime(logger, test.envSleepTime, test.envVaNoSleep, test.envVaSleepTime); actual != test.expected {
				t.Errorf("envSleepTime=[%s], envVaNoSleep=[%s], envVaSleepTime=[%s], expected=%d, actual=%d",
					test.envSleepTime,
					test.envVaNoSleep,
					test.envVaSleepTime,
					test.expected,
					actual,
				)
			}
			validateLogs(t, logBuffer.String(), test.expectedLogs)
			t.Logf("captured logs:\n%s", logBuffer.String())
		})
	}
}
