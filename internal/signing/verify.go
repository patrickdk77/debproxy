package signing

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/clearsign"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// SignInline returns a cleartext-signed document (used for InRelease).
func (k *Key) SignInline(message []byte) ([]byte, error) {
	var buf bytes.Buffer
	w, err := clearsign.Encode(&buf, k.entity.PrivateKey, nil)
	if err != nil {
		return nil, fmt.Errorf("clearsign encode: %w", err)
	}
	if _, err := w.Write(message); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	out := buf.Bytes()
	if len(out) == 0 || out[len(out)-1] != '\n' {
		out = append(out, '\n')
	}
	return out, nil
}

// SignDetached returns an armored detached signature (used for Release.gpg).
func (k *Key) SignDetached(message []byte) ([]byte, error) {
	var buf bytes.Buffer
	if err := openpgp.ArmoredDetachSign(&buf, k.entity, bytes.NewReader(message), nil); err != nil {
		return nil, fmt.Errorf("detached sign: %w", err)
	}
	out := buf.Bytes()
	if len(out) == 0 || out[len(out)-1] != '\n' {
		out = append(out, '\n')
	}
	return out, nil
}

// VerifyClearsigned verifies an inline-signed document (InRelease) against the
// keyring and returns the signed message body and the key IDs extracted from
// the signature. signerKeyIDs is populated even on verification failure, so
// callers can log which key signed the file regardless of whether it's trusted.
func VerifyClearsigned(data []byte, keyring openpgp.EntityList) (body []byte, signerKeyIDs []string, err error) {
	block, _ := clearsign.Decode(data)
	if block == nil {
		return nil, nil, fmt.Errorf("no clearsigned block found")
	}
	// Buffer the binary (dearmored) signature body so we can both verify it
	// and parse key IDs from it independently.
	sigBytes, rerr := io.ReadAll(block.ArmoredSignature.Body)
	if rerr != nil {
		return nil, nil, fmt.Errorf("read signature body: %w", rerr)
	}
	signerKeyIDs = parseKeyIDs(sigBytes)
	if _, verr := openpgp.CheckDetachedSignature(keyring, bytes.NewReader(block.Bytes), bytes.NewReader(sigBytes), nil); verr != nil {
		return nil, signerKeyIDs, fmt.Errorf("verify inline signature: %w", verr)
	}
	return block.Bytes, signerKeyIDs, nil
}

// VerifyDetached verifies a detached armored signature (Release.gpg) over body.
// signerKeyIDs is populated even on verification failure.
func VerifyDetached(body, armoredSig []byte, keyring openpgp.EntityList) (signerKeyIDs []string, err error) {
	if armBlock, aerr := armor.Decode(bytes.NewReader(armoredSig)); aerr == nil {
		if binSig, rerr := io.ReadAll(armBlock.Body); rerr == nil {
			signerKeyIDs = parseKeyIDs(binSig)
		}
	}
	if _, verr := openpgp.CheckArmoredDetachedSignature(keyring, bytes.NewReader(body), bytes.NewReader(armoredSig), nil); verr != nil {
		return signerKeyIDs, fmt.Errorf("verify detached signature: %w", verr)
	}
	return signerKeyIDs, nil
}

// parseKeyIDs extracts signer fingerprints (or key IDs if no fingerprint is
// present) from binary OpenPGP signature packets.
func parseKeyIDs(sigBytes []byte) []string {
	var ids []string
	r := packet.NewReader(bytes.NewReader(sigBytes))
	for {
		p, err := r.Next()
		if err != nil {
			break
		}
		sig, ok := p.(*packet.Signature)
		if !ok {
			continue
		}
		if len(sig.IssuerFingerprint) > 0 {
			ids = append(ids, hex.EncodeToString(sig.IssuerFingerprint))
		} else if sig.IssuerKeyId != nil {
			ids = append(ids, fmt.Sprintf("%016x", *sig.IssuerKeyId))
		}
	}
	return ids
}
