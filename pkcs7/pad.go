// Package pkcs7 implements padding for cryptographic purposes as specified
// in RFC 5652: Cryptographic Message Syntax (CMS)
package pkcs7

import "bytes"

// From the RFC
// Some content-encryption algorithms assume the
// input length is a multiple of k octets, where k > 1, and
// let the application define a method for handling inputs
// whose lengths are not a multiple of k octets. For such
// algorithms, the method shall be to pkcs7pad the input at the
// trailing end with k - (l mod k) octets all having value k -
// (l mod k), where l is the length of the input. In other
// words, the input is padded at the trailing end with one of
// the following strings:
//
// 01 -- if l mod k = k-1
// 02 02 -- if l mod k = k-2
//           .
//           .
// k k ... k k -- if l mod k = 0
//
// The padding can be removed unambiguously since all input is
// padded and no padding string is a suffix of another. This
// padding method is well-defined if and only if k < 256;
// methods for larger k are an open issue for further study

// Pad a byte slice given k (in bytes). This is commonly block size of a cipher
// like as example AES = 16. This function ensures the input data
// to the algorithm will be padded to a multiple of 16 bytes.
func Pad(b []byte, k int) []byte {
	if k < 1 {
		panic("invalid k, must be >= 1")
	}

	padBytes := k - (len(b) % k)
	if padBytes == 0 {
		// If there would be no padding, instead add an entire block size worth
		// of padding, there must always be padding so we can unambiguously
		// remove it later
		padBytes = k
	}

	padding := bytes.Repeat([]byte{byte(padBytes)}, padBytes)
	return append(b, padding...)
}

// Unpad removes pkcs7 padding
func Unpad(b []byte) []byte {
	padBytes := b[len(b)-1]
	// We should be able to count backwards, and verify that padBytes
	// all equal the padBytes integer
	for i := int(padBytes - 1); i > 0; i-- {
		if b[len(b)-i] != padBytes {
			panic("failed to pkcs7unpad pkcs7, one of the bytes was incorrect")
		}
	}

	return b[:len(b)-int(padBytes)]
}
