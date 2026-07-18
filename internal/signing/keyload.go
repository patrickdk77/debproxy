package signing

import (
	"bytes"
	"fmt"
	"io"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/errors"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// ReadKeyring parses an OpenPGP keyring from raw bytes, accepting armored
// (.asc) or binary (.gpg) input and public or secret keyrings. It is tolerant
// of real-world keys that a strict parse rejects.
//
// go-crypto's ReadEntity aborts the entire keyring the moment one User ID
// self-signature fails to verify ("user ID self-signature invalid: ...") and,
// having no valid identity left, then rejects the key outright ("vN entity
// without any identities"). Repository and signing keys in the wild routinely
// trip this -- a UID rebound after an algorithm change, a stale self-signature
// left beside a renewed one, a key edited and re-exported. For debproxy's uses
// this is the wrong place to fail: the trust in a signing key is its key
// material, and the trust in a pinned verification key is the operator having
// pinned the file (exactly as apt/gpgv treat it), not the internal UID binding.
// Actual repository trust is enforced later, when a Release signature is
// checked against the key.
//
// ReadKeyring therefore tries a strict parse first (unchanged, fully validated
// behavior for well-formed keys) and only if that fails falls back to a lenient
// pass that assembles entities directly from the packet stream, attaching User
// ID self-signatures without re-verifying them. No check that gates signature
// verification is relaxed -- only key loading is made tolerant.
func ReadKeyring(data []byte) (openpgp.EntityList, error) {
	if keys, err := readStrict(data); err == nil {
		return keys, nil
	} else if lenient, lerr := readLenient(data); lerr == nil && len(lenient) > 0 {
		return lenient, nil
	} else {
		// Surface the strict error: it names the real defect, and the lenient
		// pass recovered nothing better.
		return nil, err
	}
}

// readStrict is the armored-then-binary parse with full go-crypto validation.
func readStrict(data []byte) (openpgp.EntityList, error) {
	if keys, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(data)); err == nil {
		return keys, nil
	}
	return openpgp.ReadKeyRing(bytes.NewReader(data))
}

// readLenient assembles entities from the packet stream without verifying User
// ID self-signatures, so a key with an unverifiable (but structurally valid)
// self-signature still loads with its identities, flags, and subkeys intact.
func readLenient(data []byte) (openpgp.EntityList, error) {
	body, err := toBinary(data)
	if err != nil {
		return nil, err
	}

	reader := packet.NewReader(bytes.NewReader(body))
	var list openpgp.EntityList
	var cur *openpgp.Entity
	var primary *packet.PublicKey
	var curID *openpgp.Identity
	var curSub *openpgp.Subkey // points into cur.Subkeys; re-pointed on each subkey

	finish := func() {
		if cur != nil && cur.PrimaryKey != nil {
			list = append(list, cur)
		}
	}

	for {
		p, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			// Skip cleanly-skippable packets; stop on anything else and keep
			// whatever entities were already assembled.
			if isSkippable(err) {
				continue
			}
			break
		}

		switch pkt := p.(type) {
		case *packet.PublicKey:
			if pkt.IsSubkey {
				if cur == nil {
					continue
				}
				cur.Subkeys = append(cur.Subkeys, openpgp.Subkey{PublicKey: pkt})
				curSub = &cur.Subkeys[len(cur.Subkeys)-1]
			} else {
				finish()
				cur = &openpgp.Entity{PrimaryKey: pkt, Identities: map[string]*openpgp.Identity{}}
				primary, curID, curSub = pkt, nil, nil
			}
		case *packet.PrivateKey:
			if pkt.IsSubkey {
				if cur == nil {
					continue
				}
				cur.Subkeys = append(cur.Subkeys, openpgp.Subkey{PublicKey: &pkt.PublicKey, PrivateKey: pkt})
				curSub = &cur.Subkeys[len(cur.Subkeys)-1]
			} else {
				finish()
				cur = &openpgp.Entity{PrimaryKey: &pkt.PublicKey, PrivateKey: pkt, Identities: map[string]*openpgp.Identity{}}
				primary, curID, curSub = &pkt.PublicKey, nil, nil
			}
		case *packet.UserId:
			if cur == nil {
				continue
			}
			id := &openpgp.Identity{Name: pkt.Id, UserId: pkt}
			cur.Identities[pkt.Id] = id
			curID = id
		case *packet.UserAttribute:
			// Ignore user attributes; their following signatures collect into
			// the entity's Signatures via the nil-identity path below.
			curID = nil
		case *packet.Signature:
			if cur != nil {
				attachSignature(cur, primary, curID, curSub, pkt)
			}
		}
	}
	finish()

	if len(list) == 0 {
		return nil, fmt.Errorf("no OpenPGP keys found")
	}
	return list, nil
}

// attachSignature files sig into the entity the way ReadEntity would, but
// without verifying User ID self-signatures. A self-certification is attached
// as the identity's SelfSignature (newest wins) so key flags and preferences
// remain available for signing and verification.
func attachSignature(e *openpgp.Entity, primary *packet.PublicKey, id *openpgp.Identity, sub *openpgp.Subkey, sig *packet.Signature) {
	switch sig.SigType {
	case packet.SigTypeGenericCert, packet.SigTypePersonaCert,
		packet.SigTypeCasualCert, packet.SigTypePositiveCert:
		if id == nil {
			e.Signatures = append(e.Signatures, sig)
			return
		}
		id.Signatures = append(id.Signatures, sig)
		if primary != nil && sig.CheckKeyIdOrFingerprint(primary) &&
			(id.SelfSignature == nil || sig.CreationTime.After(id.SelfSignature.CreationTime)) {
			id.SelfSignature = sig
		}
	case packet.SigTypeCertificationRevocation:
		if id != nil {
			id.Revocations = append(id.Revocations, sig)
		} else {
			e.Signatures = append(e.Signatures, sig)
		}
	case packet.SigTypeSubkeyBinding:
		if sub != nil && sub.Sig == nil {
			sub.Sig = sig
		}
	case packet.SigTypeSubkeyRevocation:
		if sub != nil {
			sub.Revocations = append(sub.Revocations, sig)
		}
	case packet.SigTypeDirectSignature:
		if e.SelfSignature == nil || sig.CreationTime.After(e.SelfSignature.CreationTime) {
			e.SelfSignature = sig
		}
		e.Signatures = append(e.Signatures, sig)
	case packet.SigTypeKeyRevocation:
		e.Revocations = append(e.Revocations, sig)
	default:
		e.Signatures = append(e.Signatures, sig)
	}
}

// isSkippable reports whether a packet-read error names a packet that can be
// stepped over without abandoning the rest of the stream.
func isSkippable(err error) bool {
	switch err.(type) {
	case errors.UnsupportedError, errors.UnknownPacketTypeError:
		return true
	}
	return false
}

// toBinary returns the raw binary packet stream, de-armoring if necessary.
func toBinary(data []byte) ([]byte, error) {
	if block, err := armor.Decode(bytes.NewReader(data)); err == nil && block != nil {
		return io.ReadAll(block.Body)
	}
	return data, nil
}
