// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package openpgp

import (
	"bytes"
	"encoding/base64"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

func TestUserattribute_CompatibleGunPG2_3_6(t *testing.T) {

	_, err := ReadArmoredKeyRing(bytes.NewBufferString((pgpPhotoPublicOpenPGP2_3_6)))
	if err != nil {
		t.Fatal(err)
	}
}

func TestUserattributeAdd(t *testing.T) {
	entity, err := NewEntity("Golang Gopher", "Test Key", "no-reply@golang.com", nil)
	if err != nil {
		t.Fatal(err)
	}

	jpegBase64 := "/9j/4AAQSkZJRgABAQEAYABgAAD/4QAiRXhpZgAATU0AKgAAAAgAAQESAAMAAAABAAEAAAAAAAD/2wBDAAIBAQIBAQICAgICAgICAwUDAwMDAwYEBAMFBwYHBwcGBwcICQsJCAgKCAcHCg0KCgsMDAwMBwkODw0MDgsMDAz/2wBDAQICAgMDAwYDAwYMCAcIDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAz/wAARCAAyAEsDASIAAhEBAxEB/8QAHwAAAQUBAQEBAQEAAAAAAAAAAAECAwQFBgcICQoL/8QAtRAAAgEDAwIEAwUFBAQAAAF9AQIDAAQRBRIhMUEGE1FhByJxFDKBkaEII0KxwRVS0fAkM2JyggkKFhcYGRolJicoKSo0NTY3ODk6Q0RFRkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1dnd4eXqDhIWGh4iJipKTlJWWl5iZmqKjpKWmp6ipqrKztLW2t7i5usLDxMXGx8jJytLT1NXW19jZ2uHi4+Tl5ufo6erx8vP09fb3+Pn6/8QAHwEAAwEBAQEBAQEBAQAAAAAAAAECAwQFBgcICQoL/8QAtREAAgECBAQDBAcFBAQAAQJ3AAECAxEEBSExBhJBUQdhcRMiMoEIFEKRobHBCSMzUvAVYnLRChYkNOEl8RcYGRomJygpKjU2Nzg5OkNERUZHSElKU1RVVldYWVpjZGVmZ2hpanN0dXZ3eHl6goOEhYaHiImKkpOUlZaXmJmaoqOkpaanqKmqsrO0tba3uLm6wsPExcbHyMnK0tPU1dbX2Nna4uPk5ebn6Onq8vP09fb3+Pn6/9oADAMBAAIRAxEAPwD9EKKKKACipLKzm1K/gtbeMy3F1KkMSAgF3ZgqrzxySBzxzXXXnwXm0+6kt7jxZ8P4LiFzHLFJrRV43U4ZWHlcEEEEdiKAONorrf8AhUf/AFOPw7/8HZ/+NUf8Kj/6nH4d/wDg7P8A8aoA5Kitrxh4Eu/BcdjLNdaVqFpqSSNbXWnXX2iCUxtsdQ2AcqxAPGMnGcggYtABRRRQAUUUUAa3w+/5KH4d/wCwtZ/+j0r1LwH4h8DaP4q8dR+KoLF719dvHjkurM3CmASt8qfK2GDbyQACcr1xx5b8Pv8Akofh3/sLWf8A6PSvX/hB8ILDxr8S/FmvakwuIdN8RXtvDaMvyPKspfe/qBvXC+oOc8CgDx3RvDVx448Wf2foNnNIbqVzbxO2TDFu4MjcgBVIy3r0ySAev+Lv7PmofDDTLfUI5v7SsNirdSqm37NL3yP+eZPRj06HsT9GeEvhzongS4vpdJsobOTUpfNmK/oq/wB1ByQowoLHAFbVzDHeQtFIqSRyAq6MAyuDwQR3BoA+RfGP/JHPh/8A9xb/ANKxXI11ni0/8WX+Hv01X/0rWuToAKKKKACiiigCbTdQm0fVLW8t2VbizmS4iLLuAdGDKSO/IHFddqXxP0PWb+a7vPAehXN3dSNNNKbmUeY7EszY7ZYk4964uigDrf8AhPPDP/RPNB/8CpaP+E88M/8ARPNB/wDAqWuSooA3vG3jr/hL7XTbWDTbPSdP0lJVtra3LNtMrh5CWY5OWAPbHPrWDRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQB//Z"
	jpegBytes, err := base64.RawStdEncoding.DecodeString(jpegBase64)
	if err != nil {
		t.Fatal(err)
	}

	err = entity.AddPhoto(jpegBytes, nil)
	if err != nil {
		t.Fatal(err)
	}

	serializedEntity := bytes.NewBuffer(nil)
	entity.SerializePrivate(serializedEntity, nil)

	entity2, err := ReadEntity(packet.NewReader(bytes.NewBuffer(serializedEntity.Bytes())))
	if err != nil {
		t.Fatal(err)
	}

	if len(entity2.UserAttribute) != 1 {
		t.Fatal("data err, entity have no uat")
	}

	imgBytes := entity2.UserAttribute[0].UserAttribute.ImageData()
	if !bytes.Equal(imgBytes[0], jpegBytes) {
		t.Fatal("image data not equal")
	}

	if true {

		keybuf := bytes.NewBuffer(nil)
		writer, err := armor.Encode(keybuf, PrivateKeyType, nil)
		if err != nil {
			return
		}
		err = entity.SerializePrivate(writer, nil)
		if err != nil {
			return
		}
		writer.Close()
		gpgpstr := keybuf.String()
		t.Logf("data: %v\n", gpgpstr)
	}
}
