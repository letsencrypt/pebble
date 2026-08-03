package main

import (
	"errors"
	"os"
	"time"

	"github.com/letsencrypt/pebble/v2/ca"
)

const fakeClockEnvVar = "PEBBLE_FAKECLOCK"

type fixedClock struct {
	now time.Time
}

func (clk fixedClock) Now() time.Time { return clk.now }

func clockFromEnv() (ca.Clock, error) {
	value := os.Getenv(fakeClockEnvVar)
	if value == "" {
		return nil, nil
	}

	now, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return nil, errors.New("must use RFC3339 format")
	}
	return fixedClock{now: now}, nil
}
