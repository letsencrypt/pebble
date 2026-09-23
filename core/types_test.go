package core

import "testing"

func TestNewCertIDNormalizesSerial(t *testing.T) {
	akid := []byte{0x01}
	// RFC 9773 §4.1 sends the DER INTEGER value bytes, which carry a 0x00
	// sign byte when the top bit is set; certificates are indexed without it.
	withSign, err := NewCertID([]byte{0x00, 0x85, 0x9f}, akid)
	if err != nil {
		t.Fatal(err)
	}
	without, err := NewCertID([]byte{0x85, 0x9f}, akid)
	if err != nil {
		t.Fatal(err)
	}
	if withSign.SerialHex() != "859f" || without.SerialHex() != "859f" {
		t.Errorf("got %q and %q, want both %q", withSign.SerialHex(), without.SerialHex(), "859f")
	}
}
