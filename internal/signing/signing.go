package signing

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sort"
	"strings"

	"path"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
)

// KeysDir is the web-root-relative folder the public keys are served from.
const KeysDir = "keys"

// Key wraps the repository signing key (private + derived public material).
type Key struct {
	entity *openpgp.Entity
}

// FileWriter writes a published artifact relative to the web root.
type FileWriter interface {
	WriteFile(ctx context.Context, relPath string, r io.Reader, size int64) error
}

// warnIfKeyReadable logs when the private key file is readable by anyone
// other than its owner. A container Secret mount normally arrives as
// 0400 or 0440, so a looser mode means the file was placed by hand or the
// mount was misconfigured, and the key is exposed to every other process
// sharing the filesystem. Loading still proceeds: refusing would turn a
// permissions slip into an outage, and the warning is what gets it fixed.
func warnIfKeyReadable(path string) {
	info, err := os.Stat(path)
	if err != nil {
		return
	}
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		slog.Warn("signing key file is readable by group or others; "+
			"restrict it to the owner",
			"path", path, "mode", fmt.Sprintf("%04o", mode))
	}
}

// Load reads an OpenPGP private key from path, accepting armored (.asc) or
// binary (.gpg) input and tolerating keys whose User ID self-signatures do not
// verify (see ReadKeyring): only the private key material is needed to sign.
func Load(path string) (*Key, error) {
	warnIfKeyReadable(path)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("open signing key: %w", err)
	}

	list, err := ReadKeyring(data)
	if err != nil {
		return nil, fmt.Errorf("parse signing key: %w", err)
	}
	for _, e := range list {
		if e.PrivateKey != nil {
			return &Key{entity: e}, nil
		}
	}
	return nil, fmt.Errorf("no private key found in %s", path)
}

// Fingerprint returns the uppercase hex primary-key fingerprint (the unique id).
func (k *Key) Fingerprint() string {
	return strings.ToUpper(hex.EncodeToString(k.entity.PrimaryKey.Fingerprint))
}

// KeyID returns the 16-hex long key id.
func (k *Key) KeyID() string {
	return k.entity.PrimaryKey.KeyIdString()
}

// PublicKeyring returns an EntityList suitable for verifying signatures made
// by this key (round-trips through the serialized public key).
func (k *Key) PublicKeyring() (openpgp.EntityList, error) {
	bin, err := k.BinaryPublic()
	if err != nil {
		return nil, err
	}
	return openpgp.ReadKeyRing(bytes.NewReader(bin))
}

// ArmoredPublic returns the ASCII-armored (.asc) public key.
func (k *Key) ArmoredPublic() ([]byte, error) {
	var buf bytes.Buffer
	w, err := armor.Encode(&buf, openpgp.PublicKeyType, nil)
	if err != nil {
		return nil, err
	}
	if err := k.entity.Serialize(w); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// BinaryPublic returns the binary (.gpg) public key, suitable for trusted.gpg.d.
func (k *Key) BinaryPublic() ([]byte, error) {
	var buf bytes.Buffer
	if err := k.entity.Serialize(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// PublishedNames returns the web-root-relative filenames the public key is served as.
func (k *Key) PublishedNames() []string {
	fp := k.Fingerprint()
	names := []string{
		path.Join(KeysDir, fp+".asc"),
		path.Join(KeysDir, fp+".gpg"),
		path.Join(KeysDir, "debproxy.asc"),
		path.Join(KeysDir, "debproxy.gpg"),
	}
	sort.Strings(names)
	return names
}

// Publish writes the public key under the keys/ folder in both .asc and .gpg
// formats: the current key as "debproxy", and current + old keys by fingerprint.
// Fingerprint-named files are never overwritten with different content, so keys
// from prior rotations remain available to verify older snapshots.
// PublishedPayloads returns the bytes for every name in
// PublishedNames, keyed by that name. The public key is derived
// entirely from the in-memory Key, so a server holding one can answer
// /keys/* requests without touching the storage backend at all -- see
// Server.serveKeyFromMemory. Publish writes exactly this map.
func (k *Key) PublishedPayloads() (map[string][]byte, error) {
	asc, err := k.ArmoredPublic()
	if err != nil {
		return nil, fmt.Errorf("armor public key: %w", err)
	}
	bin, err := k.BinaryPublic()
	if err != nil {
		return nil, fmt.Errorf("serialize public key: %w", err)
	}

	fp := k.Fingerprint()
	return map[string][]byte{
		path.Join(KeysDir, fp+".asc"):      asc,
		path.Join(KeysDir, fp+".gpg"):      bin,
		path.Join(KeysDir, "debproxy.asc"): asc,
		path.Join(KeysDir, "debproxy.gpg"): bin,
	}, nil
}

func (k *Key) Publish(ctx context.Context, w FileWriter) ([]string, error) {
	payloads, err := k.PublishedPayloads()
	if err != nil {
		return nil, err
	}

	names := make([]string, 0, len(payloads))
	for name := range payloads {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		data := payloads[name]
		if err := w.WriteFile(ctx, name, bytes.NewReader(data), int64(len(data))); err != nil {
			return nil, fmt.Errorf("write %s: %w", name, err)
		}
	}
	return names, nil
}
