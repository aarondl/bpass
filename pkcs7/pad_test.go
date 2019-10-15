package pkcs7

import (
	"bytes"
	"testing"
)

func TestPKCS7Padding(t *testing.T) {
	t.Parallel()

	unpadded := []byte("hello")
	padded := Pad(unpadded, 8)
	expect := []byte{'h', 'e', 'l', 'l', 'o', 3, 3, 3}

	if !bytes.Equal(padded, expect) {
		t.Errorf("bytes were wrong: %v", padded)
	}

	if u := Unpad(padded); !bytes.Equal(u, unpadded) {
		t.Errorf("bytes were wrong: %v", u)
	}

	unpadded = []byte("blobpass")
	padded = Pad(unpadded, 8)
	expect = append([]byte("blobpass"), bytes.Repeat([]byte{8}, 8)...)

	if !bytes.Equal(padded, expect) {
		t.Errorf("bytes were wrong: %v", padded)
	}

	if u := Unpad(padded); !bytes.Equal(u, unpadded) {
		t.Errorf("bytes were wrong: %v", u)
	}
}
