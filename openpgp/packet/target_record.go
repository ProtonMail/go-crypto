package packet

import (
	"slices"

	"golang.org/x/crypto/sha3"

	"github.com/ProtonMail/go-crypto/openpgp/errors"
)

// TargetRecord type represents a target record in a Replacement Key subpacket
// See https://datatracker.ietf.org/doc/html/draft-ietf-openpgp-replacementkey
type TargetRecord struct {
	KeyVersion  int
	Fingerprint []byte
	Imprint     []byte
}

// Serialize writes a TargetRecord, including the prefixed record length.
// The caller must construct the Replacement Key subpacket.
// We assume the TargetRecord is well-formed, i.e. the Fingerprint and Imprint field lengths match the KeyVersion.
// If the result is nil, the record is unserializable.
func (t *TargetRecord) Serialize() []byte {
	recordLength := len(t.Fingerprint) + len(t.Imprint) + 1
	if recordLength > 255 {
		return nil
	}
	record := make([]byte, recordLength+1)
	record[0] = byte(recordLength)
	record[1] = byte(t.KeyVersion)
	copy(record[2:2+len(t.Fingerprint)], t.Fingerprint)
	copy(record[2+len(t.Fingerprint):], t.Imprint)
	return record
}

// ReadTargetRecord reads a target record from a byte slice.
// The first byte indicates the record length, followed by the record itself.
// If t and err are both nil, it means the record was read but could not be parsed,
// most likely because the key version was unknown.
// n is the total number of bytes read, i.e. the record length plus 1.
// The caller should re-slice the byte slice before reading the next record.
func ReadTargetRecord(b []byte) (t *TargetRecord, n int, err error) {
	if len(b) < 52 {
		return nil, 0, errors.StructuralError("malformed key target")
	}
	tlen := int(b[0])
	if len(b) < tlen {
		return nil, 0, errors.StructuralError("malformed key target")
	}
	t = &TargetRecord{
		KeyVersion: int(b[1]),
	}
	var fingerprintLen, imprintLen int
	switch t.KeyVersion {
	case 3:
		fingerprintLen = 16
		imprintLen = 32
	case 4:
		fingerprintLen = 20
		imprintLen = 32
	case 5, 6:
		fingerprintLen = 32
		imprintLen = 32
	default:
		return nil, tlen + 1, nil
	}
	if fingerprintLen+imprintLen+1 != tlen {
		return nil, 0, errors.StructuralError("malformed key target")
	}
	t.Fingerprint = b[2 : 2+fingerprintLen]
	t.Imprint = b[2+fingerprintLen:]
	return t, tlen + 1, nil
}

// NewTargetRecord creates a target record pointing to the supplied public key.
// The public key must be a primary key, not a subkey.
// If the key version is unknown, it returns nil.
func NewTargetRecord(k *PublicKey) *TargetRecord {
	var imprint []byte
	switch k.Version {
	case 4, 5, 6:
		imprint = k.Imprint(sha3.New256())
	default:
		return nil
	}
	return &TargetRecord{
		KeyVersion:  k.Version,
		Fingerprint: k.Fingerprint,
		Imprint:     imprint,
	}
}

// Equals tests target records for equality.
func (t1 *TargetRecord) Equals(t2 *TargetRecord) bool {
	return t1.KeyVersion == t2.KeyVersion &&
		slices.Compare(t1.Fingerprint, t2.Fingerprint) == 0 &&
		slices.Compare(t1.Imprint, t2.Imprint) == 0
}
