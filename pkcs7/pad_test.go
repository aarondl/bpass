package pkcs7

import (
	"bytes"
	"testing"
)

func TestPKCS7Padding(t *testing.T) {
	t.Parallel()

	tests := []struct {
		In   []byte
		Size int
		Want []byte
	}{
		{
			In:   []byte{},
			Size: 8,
			Want: bytes.Repeat([]byte{8}, 8),
		},
		{
			In:   []byte{},
			Size: 1,
			Want: bytes.Repeat([]byte{1}, 1),
		},
		{
			In:   []byte("hello"),
			Size: 8,
			Want: append([]byte("hello"), 3, 3, 3),
		},
		{
			In:   []byte("blobpass"),
			Size: 8,
			Want: append([]byte("blobpass"), bytes.Repeat([]byte{8}, 8)...),
		},
	}

	for i, test := range tests {
		padded := Pad(test.In, test.Size)

		if !bytes.Equal(test.Want, padded) {
			t.Errorf(`%d) want: "%X", got: "%X"`, i, test.Want, padded)
		}

		unpadded, err := Unpad(padded)
		if err != nil {
			t.Errorf("%d) %v", i, err)
		}

		if !bytes.Equal(test.In, unpadded) {
			t.Errorf(`%d) want: "%X", got: "%X"`, i, test.In, unpadded)
		}
	}
}

func TestPKCS7UnpadErrors(t *testing.T) {
	t.Parallel()

	_, err := Unpad(nil)
	if err != errEmptySlice {
		t.Error("error was wrong:", err)
	}

	_, err = Unpad([]byte{1, 255})
	if err != errPaddingAmountImpossible {
		t.Error("error was wrong:", err)
	}
	_, err = Unpad([]byte{2})
	if err != errPaddingAmountImpossible {
		t.Error("error was wrong:", err)
	}

	_, err = Unpad([]byte{1, 3, 2})
	if err != errPaddingInvalid {
		t.Error("error was wrong:", err)
	}
}
