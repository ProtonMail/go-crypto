package packet

import (
	"io"
)

type Trust struct {
	Contents []byte
}

// parse performs no checks, just imports the raw packet body contents.
// It is the application's responsibility to check the contents.
func (t *Trust) parse(reader io.Reader) (err error) {
	t.Contents, err = io.ReadAll(reader)
	return
}

// Serialize marshals the trust packet to writer in the form of an OpenPGP packet, including header.
func (t *Trust) Serialize(writer io.Writer) error {
	err := serializeHeader(writer, packetTypeTrust, len(t.Contents))
	if err != nil {
		return err
	}
	_, err = writer.Write(t.Contents)
	return err
}
