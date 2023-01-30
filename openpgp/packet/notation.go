package packet

// Notation type represents a Notation Data subpacket
// see https://tools.ietf.org/html/rfc4880#section-5.2.3.16
type Notation struct {
	Name            string
	Value           []byte
	IsCritical      bool
	IsHumanReadable bool
}

func (not *Notation) getData() []byte {
	nameData := []byte(not.Name)
	nameLen := len(nameData)
	valueLen := len(not.Value)

	data := make([]byte, 8+nameLen+valueLen)
	if not.IsHumanReadable {
		data[0] = 0x80
	}

	data[4] = byte(nameLen >> 8)
	data[5] = byte(nameLen)
	data[6] = byte(valueLen >> 8)
	data[7] = byte(valueLen)
	copy(data[8:8+nameLen], nameData)
	copy(data[8+nameLen:], not.Value)
	return data
}
