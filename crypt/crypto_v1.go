package crypt

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha512"
	"fmt"

	"github.com/aarondl/bpass/pkcs7"
	"golang.org/x/crypto/scrypt"
)

// encryptV1 creates this format:
// 8:magic|8:version|32:passphraseSalt|blockSize:iv|(64:sha512|data)
// where the sha512 all fields (magic, version, passphraseSalt, blockSize, data)
func encryptV1(c config, key, salt, plaintext []byte) (encrypted []byte, err error) {
	cipherSuite, err := cipherSuite(c)
	if err != nil {
		return nil, err
	}

	ciphers, err := makeCiphers(key, cipherSuite)
	if err != nil {
		return nil, err
	}

	// Create an iv for all ciphers at once
	iv := make([]byte, c.blockSize)
	if n, err := rand.Read(iv); n != c.blockSize || err != nil {
		return nil, fmt.Errorf("failed to get randomness for iv: %w", err)
	}

	plaintextHeader := make([]byte, magicLen+c.saltSize+c.blockSize)
	copy(plaintextHeader, fmt.Sprintf("%s%08d", magicStr, c.version))
	copy(plaintextHeader[magicLen:], salt)
	copy(plaintextHeader[magicLen+c.saltSize:], iv)

	sha := sha512.New()
	_, _ = sha.Write(plaintextHeader)
	_, _ = sha.Write(plaintext)
	shaSum := sha.Sum(nil)

	work := make([]byte, sha512.Size+len(plaintext))
	copy(work, shaSum)
	copy(work[sha512.Size:], plaintext)

	ivOffset := 0
	for i, c := range ciphers {
		cipherBlockSize := cipherSuite[i].BlockSize

		// Pull out blockSize iv bytes for our cipher
		cbc := cipher.NewCBCEncrypter(c, iv[ivOffset:ivOffset+cipherBlockSize])
		ivOffset += cipherBlockSize

		// pad & encrypt
		work = pkcs7.Pad(work, cipherBlockSize)
		cbc.CryptBlocks(work, work)
	}

	return append(plaintextHeader, work...), nil
}

func decryptV1(c config, passphrase, encrypted []byte) (plaintext, key, salt []byte, err error) {
	suite, err := cipherSuite(c)
	if err != nil {
		return nil, nil, nil, err
	}

	// Pull salt out and derive key
	salt = encrypted[magicLen : magicLen+c.saltSize]
	key, err = c.keygen(c, passphrase, salt)
	if err != nil {
		return nil, nil, nil, err
	}

	ciphers, err := makeCiphers(key, suite)
	if err != nil {
		return nil, nil, nil, err
	}

	// Copy the ciphertext to where we can decode it
	ciphertext := make([]byte, len(encrypted)-magicLen-c.saltSize-c.blockSize)
	copy(ciphertext, encrypted[magicLen+c.saltSize+c.blockSize:])

	iv := encrypted[magicLen+c.saltSize : magicLen+c.saltSize+c.blockSize]
	ivOffset := len(iv)
	for i := len(ciphers) - 1; i >= 0; i-- {
		c := ciphers[i]

		cipherBlockSize := c.BlockSize()
		// Read iv encrypted reverse since we're doing each algorithm encrypted reverse now
		cbc := cipher.NewCBCDecrypter(c, iv[ivOffset-cipherBlockSize:ivOffset])
		ivOffset -= cipherBlockSize

		// decrypt & discard padding
		cbc.CryptBlocks(ciphertext, ciphertext)
		ciphertext, err = pkcs7.Unpad(ciphertext)
		if err != nil {
			// We assume we aren't getting padding failures unless we've
			// been given the wrong passphrase to deal with.
			return nil, nil, nil, ErrWrongPassphrase
		}
	}

	origShaSum := ciphertext[:sha512.Size]
	plaintext = ciphertext[sha512.Size:]

	// Verify integrity
	sha := sha512.New()
	_, _ = sha.Write(encrypted[:magicLen])
	_, _ = sha.Write(salt)
	_, _ = sha.Write(iv)
	_, _ = sha.Write(plaintext)
	shaSum := sha.Sum(nil)

	if !bytes.Equal(origShaSum, shaSum) {
		return nil, nil, nil, ErrWrongPassphrase
	}

	return plaintext, key, salt, nil
}

func deriveKeyV1(c config, passphrase, salt []byte) ([]byte, error) {
	return scrypt.Key(passphrase, salt, 524288 /* 2<<18 */, 8, 1, c.keySize)
}
