package crypt

import (
	"bytes"
	"sort"
	"testing"
)

func TestCrypt(t *testing.T) {
	t.Parallel()

	if testing.Short() {
		t.Skip("skipping long test")
	}

	passphrase := []byte("hunter42")
	plaintext := []byte("plaintext goes here")

	var versionNumbers []int
	for v := range versions {
		versionNumbers = append(versionNumbers, v)
	}

	sort.Ints(versionNumbers)

	for _, v := range versionNumbers {
		key, salt, err := DeriveKey(v, passphrase)
		if err != nil {
			t.Errorf("%d) failed to derive key: %v", v, err)
		}

		var p Params
		p.SetSingleUser(key, salt)
		ciphertext, err := Encrypt(v, &p, plaintext)
		if err != nil {
			t.Fatalf("%d) %v", v, err)
		}

		if bytes.Contains(ciphertext, plaintext) {
			t.Errorf("%d) the plain text is visible", v)
		}

		version, p, gotPlaintext, err := Decrypt(nil, passphrase, nil, nil, ciphertext)
		if err != nil {
			t.Error(err)
		}

		if version != v {
			t.Error("version was wrong")
		}

		if !bytes.Equal(key, p.Keys[0]) {
			t.Error("key was wrong")
		}
		if !bytes.Equal(salt, p.Salts[0]) {
			t.Error("salt was wrong")
		}

		if !bytes.Equal(plaintext, gotPlaintext) {
			t.Errorf("want: %s, got: %s", plaintext, gotPlaintext)
		}

		// Test fast path decryption where we don't derive the key
		_, _, gotPlaintext, err = Decrypt(nil, nil, key, salt, ciphertext)
		if err != nil {
			t.Fatalf("%d) %v", v, err)
		}

		if !bytes.Equal(plaintext, gotPlaintext) {
			t.Errorf("want: %s, got: %s", plaintext, gotPlaintext)
		}
	}
}

func TestCryptMulti(t *testing.T) {
	t.Parallel()

	if testing.Short() {
		t.Skip("skipping long test")
	}

	passphrase := []byte("hunter42")
	plaintext := []byte("plaintext goes here")

	var versionNumbers []int
	for v := range versions {
		versionNumbers = append(versionNumbers, v)
	}

	sort.Ints(versionNumbers)

	for _, v := range versionNumbers {
		key1, salt1, err := DeriveKey(v, passphrase)
		if err != nil {
			t.Errorf("%d) failed to derive key: %v", v, err)
		}
		key2, salt2, err := DeriveKey(v, passphrase)
		if err != nil {
			t.Errorf("%d) failed to derive key: %v", v, err)
		}

		var p Params
		p.AddUser("user1", key1, salt1)
		p.AddUser("user2", key2, salt2)

		ciphertext, err := Encrypt(v, &p, plaintext)
		if err != nil {
			t.Fatalf("%d) %v", v, err)
		}

		if bytes.Contains(ciphertext, plaintext) {
			t.Errorf("%d) the plain text is visible", v)
		}

		version, p, gotPlaintext, err := Decrypt([]byte("user1"), passphrase, nil, nil, ciphertext)
		if err != nil {
			t.Error(err)
		}

		if version != v {
			t.Error("version was wrong")
		}

		if p.NUsers != 2 {
			t.Error("nusers was wrong:", p.NUsers)
		}

		if !bytes.Equal(key1, p.Keys[0]) {
			t.Errorf("%d) key was wrong", v)
		}
		if !bytes.Equal(salt1, p.Salts[0]) {
			t.Errorf("%d) salt was wrong", v)
		}
		if p.Keys[1] != nil {
			t.Errorf("%d) key was wrong", v)
		}
		if !bytes.Equal(salt2, p.Salts[1]) {
			t.Errorf("%d) salt was wrong", v)
		}

		if len(p.IVs) != 2 {
			t.Error("ivs was wrong")
		}
		for _, i := range p.IVs {
			if len(i) == 0 {
				t.Errorf("%d) ivs[%d] was empty", v, i)
			}
		}
		if len(p.MKeys) != 2 {
			t.Error("mkeys was wrong")
		}
		for _, i := range p.MKeys {
			if len(i) == 0 {
				t.Errorf("%d) mkeys[%d] was empty", v, i)
			}
		}

		if len(p.IVM) == 0 {
			t.Errorf("%d) IVM was empty", v)
		}
		if len(p.Master) == 0 {
			t.Errorf("%d) master was empty", v)
		}

		if !bytes.Equal(plaintext, gotPlaintext) {
			t.Errorf("want: %s, got: %s", plaintext, gotPlaintext)
		}

		// Test fast path decryption where we don't derive the key
		_, _, gotPlaintext, err = Decrypt([]byte("user2"), nil, key2, salt2, ciphertext)
		if err != nil {
			t.Fatalf("%d) %v", v, err)
		}

		if !bytes.Equal(plaintext, gotPlaintext) {
			t.Errorf("want: %s, got: %s", plaintext, gotPlaintext)
		}
	}
}

func TestDecryptV0(t *testing.T) {
	t.Parallel()

	t.Skip("Go impl of SEED does not work")

	passphrase := []byte("hunter42")
	plaintext := []byte("plaintext goes here")

	ct := []byte{
		0x6b, 0x6e, 0x69, 0x6f, 0x70, 0x61, 0x73, 0x73, 0x30, 0x30, 0x30, 0x30,
		0x30, 0x30, 0x30, 0x31, 0x2e, 0x7a, 0x99, 0xa2, 0x48, 0xfe, 0x27, 0xfa,
		0x10, 0x33, 0x53, 0xee, 0x36, 0x2e, 0xdd, 0xbf, 0x19, 0x90, 0xa3, 0x12,
		0xdb, 0x14, 0x4b, 0xdb, 0x16, 0x01, 0x54, 0x12, 0xac, 0x9a, 0xb3, 0x68,
		0x3c, 0xcb, 0x5e, 0xec, 0xef, 0x70, 0x59, 0xdb, 0x09, 0xd3, 0x54, 0x10,
		0x60, 0x2f, 0x24, 0x4f, 0x08, 0x3a, 0xfe, 0x86, 0xab, 0xfb, 0xc8, 0xe0,
		0x0b, 0x45, 0x69, 0xcd, 0x4d, 0xe0, 0xc7, 0xb1, 0xb1, 0xbf, 0xf8, 0x18,
		0x4c, 0xdf, 0x96, 0x0e, 0x50, 0x8b, 0x9e, 0x59, 0xc1, 0x6c, 0xae, 0x60,
		0x91, 0x7b, 0x4d, 0x1a, 0xf7, 0x0a, 0xb4, 0x4f, 0x5d, 0x41, 0xee, 0x6a,
		0x1a, 0x1a, 0x59, 0x90, 0x91, 0x6d, 0xee, 0xdd, 0x86, 0xe8, 0x30, 0x7c,
		0xe8, 0xd0, 0x0e, 0x02, 0x5f, 0x94, 0x6a, 0xf1, 0x7c, 0xcc, 0x7d, 0x62,
		0x65, 0xf6, 0x12, 0x01, 0x4a, 0x75, 0xc4, 0x11, 0xce, 0x89, 0x0d, 0x31,
		0x6b, 0x9e, 0x2e, 0xe8, 0x79, 0xbe, 0xa4, 0x9f, 0x1a, 0xce, 0x1f, 0xff,
		0xd6, 0x8a, 0xcd, 0xb5, 0xf8, 0xfc, 0x5f, 0x6c, 0x0a, 0xb9, 0xcf, 0x4b,
		0xb6, 0x8f, 0x72, 0x7f, 0x65, 0xbd, 0x57, 0x13, 0xe8, 0xc1, 0x19, 0xb3,
		0xb0, 0xb1, 0x5c, 0xcc, 0xf5, 0x38, 0x0a, 0xc1, 0x99, 0x6a, 0x90, 0x17,
		0x67, 0xc1, 0x11, 0xb0, 0x4d, 0x86, 0x2a, 0x1e, 0x32, 0x63, 0xb2, 0x7b,
		0xef, 0xff, 0xfc, 0x12,
	}

	pt, key, salt, err := decryptV0(passphrase, ct)
	if err != nil {
		t.Error(err)
	}
	if len(key) == 0 {
		t.Error("key was empty")
	}
	if len(salt) == 0 {
		t.Error("salt was empty")
	}

	if !bytes.Equal(pt, plaintext) {
		t.Errorf("pt was wrong: %s", pt)
	}
}

func TestKeyDerivation(t *testing.T) {
	t.Parallel()

	if testing.Short() {
		t.Skip("skipping long test")
	}

	testPass := []byte("hunter42")
	testSalt := []byte("abcdefgh12345678")

	// 32+32+16+16 is the combined key size of the version 1 algorithms
	keysize := 32 + 32 + 16 + 16
	key, err := deriveKeyV1(config{keySize: keysize}, testPass, testSalt)
	if err != nil {
		t.Error(err)
	}

	if len(key) != keysize {
		t.Error("keysize was wrong:", len(key))
	}

	want := []byte{
		0xD4, 0x3B, 0x74, 0x9F, 0x72, 0x65, 0xAC, 0x1A, 0xE8, 0x7B, 0xFD, 0xF6, 0xE4, 0xA7, 0x14, 0x92, 0x78, 0xA9, 0x07, 0x3F, 0xDE, 0x36,
		0xA1, 0x26, 0xBF, 0x6C, 0xCD, 0x51, 0x93, 0x47, 0xCA, 0xAF, 0xE4, 0x71, 0x77, 0xFD, 0xF0, 0xA3, 0x8E, 0xAB, 0x3F, 0x9A, 0x98, 0x8F,
		0x51, 0xF0, 0xCC, 0x92, 0x69, 0xDC, 0x16, 0x8A, 0xEB, 0x0A, 0x45, 0x1B, 0xEB, 0x4B, 0x58, 0xAF, 0x66, 0x82, 0xB7, 0x6C, 0x48, 0x42,
		0xEB, 0x83, 0x0B, 0xD7, 0x1A, 0x08, 0x12, 0x63, 0x3D, 0x2B, 0x1E, 0xE8, 0x28, 0x5A, 0xC2, 0x36, 0xD0, 0xE0, 0xB3, 0xB2, 0x4A, 0xE0,
		0xE6, 0xAF, 0x08, 0x8F, 0x1B, 0x17, 0x96, 0xFA,
	}

	if !bytes.Equal(want, key) {
		t.Errorf("key was not equal: %#v", key)
	}
}
