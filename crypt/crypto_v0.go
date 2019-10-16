package crypt

import (
	"bytes"
	"crypto/cipher"

	"github.com/aarondl/upass/pkcs7"
)

func decryptV0(passphrase, encrypted []byte) (plaintext, key, salt []byte, err error) {
	const keySize = 32 + 32 + 16 + 16

	// We already know our header is taken care of because we're in here
	encrypted = encrypted[16:]

	// Salt is next
	salt = encrypted[:32]
	encrypted = encrypted[32:]

	// Derive the key
	key, err = deriveKeyV1(config{keySize: keySize}, passphrase, salt)
	if err != nil {
		return nil, nil, nil, err
	}

	// Grab iv which is sized incorrectly for its purpose
	iv := encrypted[:keySize]
	ciphertext := encrypted[keySize:]

	suite, err := cipherSuite(config{algs: []string{"AES", "Camellia", "CAST5", "SEED"}})
	if err != nil {
		return nil, nil, nil, err
	}

	ciphers, err := makeCiphers(key, suite)
	if err != nil {
		return nil, nil, nil, err
	}

	ivOffset := len(iv)
	for i := len(ciphers) - 1; i >= 0; i-- {
		c := ciphers[i]

		cipherBlockSize := suite[i].BlockSize
		cipherKeySize := suite[i].KeySize
		ivOffset -= cipherKeySize

		// Read iv encrypted reverse since we're doing each algorithm encrypted
		// reverse now but also for v0 read it incorrectly.
		// From the ivOffset, read cipherBlockSize, and then offset by keySize
		cbc := cipher.NewCBCDecrypter(c, iv[ivOffset:ivOffset+cipherBlockSize])

		// decrypt & discard padding
		cbc.CryptBlocks(ciphertext, ciphertext)
		ciphertext, err = pkcs7.Unpad(ciphertext)
		if err != nil {
			// We assume we aren't getting padding failures unless we've
			// been given the wrong passphrase to deal with.
			return nil, nil, nil, ErrWrongPassphrase
		}
	}

	if !bytes.Equal(ciphertext[:len(v0Header)], v0Header) {
		return nil, nil, nil, ErrWrongPassphrase
	}

	return ciphertext, key, salt, nil
}
