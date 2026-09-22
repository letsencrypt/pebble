package main

import (
	"testing"
	"time"
)

func TestClockFromEnv(t *testing.T) {
	t.Run("unset", func(t *testing.T) {
		t.Setenv(fakeClockEnvVar, "")

		clk, err := clockFromEnv()
		if err != nil {
			t.Fatal(err)
		}
		if clk != nil {
			t.Fatal("expected the default wall clock")
		}
	})

	t.Run("valid", func(t *testing.T) {
		now := time.Date(2030, time.January, 2, 3, 4, 5, 0, time.UTC)
		t.Setenv(fakeClockEnvVar, now.Format(time.RFC3339))

		clk, err := clockFromEnv()
		if err != nil {
			t.Fatal(err)
		}
		if got := clk.Now(); !got.Equal(now) {
			t.Fatalf("unexpected time: got %s, want %s", got, now)
		}
	})

	t.Run("invalid", func(t *testing.T) {
		t.Setenv(fakeClockEnvVar, "not-a-time")
		if _, err := clockFromEnv(); err == nil {
			t.Fatal("expected an error")
		}
	})
}
