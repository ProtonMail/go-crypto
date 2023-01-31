package packet

import (
	"bytes"
	"testing"
)

func TestNotationGetData(t *testing.T) {
	notation := Notation{
		Name:            "test@proton.me",
		Value:           []byte("test-value"),
		IsCritical:      true,
		IsHumanReadable: true,
	}
	expected := []byte{0x80, 0, 0, 0, 0, 14, 0, 10}
	expected = append(expected, []byte(notation.Name)...)
	expected = append(expected, []byte(notation.Value)...)
	data := notation.getData()
	if !bytes.Equal(expected, data) {
		t.Fatalf("Expected %s, got %s", expected, data)
	}
}

func TestNotationGetDataNotHumanReadable(t *testing.T) {
	notation := Notation{
		Name:            "test@proton.me",
		Value:           []byte("test-value"),
		IsCritical:      true,
		IsHumanReadable: false,
	}
	expected := []byte{0, 0, 0, 0, 0, 14, 0, 10}
	expected = append(expected, []byte(notation.Name)...)
	expected = append(expected, []byte(notation.Value)...)
	data := notation.getData()
	if !bytes.Equal(expected, data) {
		t.Fatalf("Expected %s, got %s", expected, data)
	}
}
