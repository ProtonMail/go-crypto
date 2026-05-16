package packet

import (
	"github.com/ProtonMail/go-crypto/openpgp/errors"
)

// TargetRecord type represents a target record in a Replacement Key subpacket
// See https://datatracker.ietf.org/doc/html/draft-ietf-openpgp-replacementkey
type TargetRecord struct {
	KeyVersion  int
	Fingerprint []byte
	Imprint     []byte
}

// Serialize writes a TargetRecord, including record length; caller must construct the Replacement Key subpacket.
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

// ReadTargetRecord reads a target record from the wire, where the first octet is the record length.
// If kt and err are both nil, it means that the record was well-formed but could not be read,
// for example if the key version was unknown.
// n is the total number of bytes read, i.e. the record length plus 1.
func ReadTargetRecord(r []byte) (kt *TargetRecord, n int, err error) {
	if len(r) < 52 {
		return nil, 0, errors.StructuralError("malformed key target")
	}
	ktlen := int(r[0])
	if len(r) < ktlen {
		return nil, 0, errors.StructuralError("malformed key target")
	}
	kt = &TargetRecord{
		KeyVersion: int(r[1]),
	}
	var fingerprintLen, imprintLen int
	switch kt.KeyVersion {
	case 3:
		fingerprintLen = 16
		imprintLen = 32
	case 4:
		fingerprintLen = 20
		imprintLen = 32
	case 5:
		fingerprintLen = 32
		imprintLen = 32
	case 6:
		fingerprintLen = 32
		imprintLen = 32
	default:
		return nil, ktlen + 1, nil
	}
	if fingerprintLen+imprintLen+1 != ktlen {
		return nil, 0, errors.StructuralError("malformed key target")
	}
	kt.Fingerprint = r[1 : 1+fingerprintLen]
	kt.Imprint = r[1+fingerprintLen:]
	return kt, ktlen + 1, nil
}
