// Package dkim creates and verifies DKIM signatures, as specified in RFC 6376.
package dkim

import (
	"time"
)

var now = time.Now

const headerFieldName = "DKIM-Signature"
