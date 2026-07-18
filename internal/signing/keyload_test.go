package signing

import (
	"bytes"
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
)

// tamperUID flips a byte inside the User ID text of a binary keyring, leaving
// the original self-signature (made over the original text) in place. The
// result is a key whose UID self-signature no longer verifies -- reproducing
// go-crypto's fatal "user ID self-signature invalid: ... verification failure".
// The UID text length is unchanged, so packet framing stays valid.
func tamperUID(t *testing.T, binKeyring []byte) []byte {
	t.Helper()
	// The email is part of the UID text and appears only in the UID packet.
	marker := []byte("repro@example.test")
	i := bytes.Index(binKeyring, marker)
	if i < 0 {
		t.Fatal("UID text not found in keyring")
	}
	out := append([]byte(nil), binKeyring...)
	out[i] ^= 0x20 // 'r' -> 'R': same length, breaks the self-signature hash
	return out
}

func newTestSecretKeyBinary(t *testing.T) []byte {
	t.Helper()
	e, err := openpgp.NewEntity("Repro Key", "", "repro@example.test", nil)
	if err != nil {
		t.Fatalf("NewEntity: %v", err)
	}
	var buf bytes.Buffer
	if err := e.SerializePrivate(&buf, nil); err != nil {
		t.Fatalf("SerializePrivate: %v", err)
	}
	return buf.Bytes()
}

// TestReadKeyring_ToleratesInvalidUIDSelfSig is the direct regression for the
// deployed error: "parse signing key: openpgp: invalid data: user ID
// self-signature invalid: ... RSA verification failure".
func TestReadKeyring_ToleratesInvalidUIDSelfSig(t *testing.T) {
	broken := tamperUID(t, newTestSecretKeyBinary(t))

	// The strict parse must reproduce the reported failure...
	if _, err := readStrict(broken); err == nil {
		t.Fatal("readStrict accepted a key with an invalid UID self-signature; " +
			"cannot prove the lenient path is exercised")
	} else {
		t.Logf("strict parse fails as expected: %v", err)
	}

	// ...and ReadKeyring must recover the key material anyway.
	kr, err := ReadKeyring(broken)
	if err != nil {
		t.Fatalf("ReadKeyring rejected a key with only an invalid UID self-sig: %v", err)
	}
	if len(kr) == 0 || kr[0].PrivateKey == nil {
		t.Fatalf("ReadKeyring returned no usable private key (entities=%d)", len(kr))
	}
	t.Logf("lenient parse recovered private key, entities=%d", len(kr))
}

// TestReadKeyring_ToleratesMissingArmorCRC confirms an ASCII-armored key with
// its optional CRC-24 checksum line ("=XXXX" before -----END-----) removed
// still loads. RFC 9580 made the checksum optional and go-crypto no longer
// requires or checks it.
func TestReadKeyring_ToleratesMissingArmorCRC(t *testing.T) {
	e, err := openpgp.NewEntity("CRCless Key", "", "crcless@example.test", nil)
	if err != nil {
		t.Fatalf("NewEntity: %v", err)
	}
	var buf bytes.Buffer
	w, err := armor.Encode(&buf, openpgp.PublicKeyType, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Serialize(w); err != nil {
		t.Fatal(err)
	}
	w.Close()

	armored := buf.String()
	// Drop the "=XXXX" checksum line that precedes the END line.
	var kept []string
	for _, line := range strings.Split(armored, "\n") {
		trimmed := strings.TrimSpace(line)
		if len(trimmed) == 5 && trimmed[0] == '=' {
			continue // the CRC-24 line
		}
		kept = append(kept, line)
	}
	stripped := strings.Join(kept, "\n")
	if strings.Contains(stripped, "\n=") {
		t.Fatal("failed to strip the CRC line")
	}

	kr, err := ReadKeyring([]byte(stripped))
	if err != nil {
		t.Fatalf("ReadKeyring(CRC-less armored key) = %v, want success", err)
	}
	if len(kr) != 1 {
		t.Fatalf("entities = %d, want 1", len(kr))
	}
}

// TestReadKeyring_StrictPathUnchanged confirms a well-formed key still takes the
// strict path and its UID self-signature survives (leniency does not fire).
func TestReadKeyring_StrictPathUnchanged(t *testing.T) {
	good := newTestSecretKeyBinary(t)
	kr, err := ReadKeyring(good)
	if err != nil {
		t.Fatalf("ReadKeyring(good): %v", err)
	}
	if len(kr) != 1 {
		t.Fatalf("entities = %d, want 1", len(kr))
	}
	// A well-formed key keeps a verified self-signature (identity present).
	if len(kr[0].Identities) == 0 {
		t.Error("well-formed key lost its identities on the strict path")
	}
}

