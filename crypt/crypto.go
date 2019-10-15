package crypt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha512"
	"errors"
	"fmt"
	"strconv"

	"github.com/aarondl/upass/pkcs7"
	"github.com/enceve/crypto/camellia"
	"github.com/geeksbaek/seed"
	"golang.org/x/crypto/cast5"
	"golang.org/x/crypto/scrypt"
)

// Error returns from decoding
var (
	ErrInvalidMagic   = errors.New("invalid magic string")
	ErrInvalidVersion = errors.New("invalid version")
)

const (
	magicLen   = 16
	saltLen    = 32
	maxVersion = 99999999
)

var (
	magicStr = []byte("blobpass")

	algorithms = map[string]cipherAlg{
		"AES":      {KeySize: 32, CTOR: aes.NewCipher},
		"Camellia": {KeySize: 32, CTOR: camellia.NewCipher},
		"CAST5":    {KeySize: 16, CTOR: func(key []byte) (cipher.Block, error) { return cast5.NewCipher(key) }},
		"SEED":     {KeySize: 16, CTOR: seed.NewCipher},
	}

	// cipherSuites are defined in encryption order for their version
	cipherSuites = map[int][]string{
		1: {"AES", "Camellia", "CAST5", "SEED"},
	}
)

type cipherAlg struct {
	KeySize int
	CTOR    func(key []byte) (cipher.Block, error)
}

// Encrypt data. The version corresponds to the password derivation function
// as well as the cipher suite used. Password is automatically salted.
// The full output of this function is required for decryption as the version
// numbers, salts and ivs inform the decryption.
func Encrypt(version int, password, plaintext []byte) (encrypted []byte, err error) {
	if version > maxVersion {
		return nil, ErrInvalidVersion
	}

	suite, err := cipherSuite(version)
	if err != nil {
		return nil, err
	}

	// Secure random salt for password derivation
	salt := make([]byte, saltLen)
	if n, err := rand.Read(salt); n != saltLen || err != nil {
		return nil, fmt.Errorf("failed to get randomness for salt: %w", err)
	}

	keySize := calcKeySize(suite)
	key, err := deriveKey(version, password, salt, keySize)
	if err != nil {
		return nil, err
	}

	ciphers, err := makeCiphers(key, suite)
	if err != nil {
		return nil, err
	}

	// Create an iv for all ciphers at once
	blockSize := calcBlockSize(ciphers)
	iv := make([]byte, blockSize)
	if n, err := rand.Read(iv); n != blockSize || err != nil {
		return nil, fmt.Errorf("failed to get randomness for iv: %w", err)
	}

	// The output we're constructing in two parts looks like this:
	// The parens represent encryption, the plaintextHeader has 4 components
	// while the encrypted part has 2, at the end we join them to create
	// the full output.
	// 8:magic|8:version|32:passwordSalt|blockSize:iv|(64:sha512|data)
	plaintextHeader := make([]byte, magicLen+saltLen+blockSize)
	copy(plaintextHeader, fmt.Sprintf("%s%08d", magicStr, version))
	copy(plaintextHeader[magicLen:], salt)
	copy(plaintextHeader[magicLen+saltLen:], iv)

	sha := sha512.New()
	_, _ = sha.Write(plaintextHeader)
	_, _ = sha.Write(plaintext)
	shaSum := sha.Sum(nil)

	work := make([]byte, sha512.Size+len(plaintext))
	copy(work, shaSum)
	copy(work[sha512.Size:], plaintext)

	ivOffset := 0
	for _, c := range ciphers {
		cipherBlockSize := c.BlockSize()
		// Pull out blockSize iv bytes for our cipher
		cbc := cipher.NewCBCEncrypter(c, iv[ivOffset:ivOffset+cipherBlockSize])
		ivOffset += cipherBlockSize

		// pad & encrypt
		work = pkcs7.Pad(work, cipherBlockSize)
		cbc.CryptBlocks(work, work)
	}

	return append(plaintextHeader, work...), nil
}

// Decrypt data, requires the full input (all headers) returned from Encrypt
func Decrypt(password, encrypted []byte) (plaintext []byte, err error) {
	version, err := verifyMagic(encrypted)
	if err != nil {
		return nil, err
	}

	suite, err := cipherSuite(version)
	if err != nil {
		return nil, err
	}

	// Pull salt out and derive key
	salt := encrypted[magicLen : magicLen+saltLen]
	keySize := calcKeySize(suite)
	key, err := deriveKey(version, password, salt, keySize)
	if err != nil {
		return nil, err
	}

	ciphers, err := makeCiphers(key, suite)
	if err != nil {
		return nil, err
	}

	// Get size of iv
	blockSize := calcBlockSize(ciphers)

	// Copy the ciphertext to where we can decode it
	work := make([]byte, len(encrypted)-magicLen-saltLen-blockSize)
	copy(work, encrypted[magicLen+saltLen+blockSize:])

	iv := encrypted[magicLen+saltLen : magicLen+saltLen+blockSize]
	ivOffset := len(iv)
	for i := len(ciphers) - 1; i >= 0; i-- {
		c := ciphers[i]

		cipherBlockSize := c.BlockSize()
		// Read iv encrypted reverse since we're doing each algorithm encrypted reverse now
		cbc := cipher.NewCBCDecrypter(c, iv[ivOffset-cipherBlockSize:ivOffset])
		ivOffset -= cipherBlockSize

		// decrypt & discard padding
		cbc.CryptBlocks(work, work)
		work = pkcs7.Unpad(work)
	}

	origShaSum := work[:sha512.Size]
	plaintext = work[sha512.Size:]

	// Verify integrity
	sha := sha512.New()
	_, _ = sha.Write(encrypted[:magicLen])
	_, _ = sha.Write(salt)
	_, _ = sha.Write(iv)
	_, _ = sha.Write(plaintext)
	shaSum := sha.Sum(nil)

	if !bytes.Equal(origShaSum, shaSum) {
		return nil, errors.New("integrity of archive could not be verified")
	}

	// Remove the header before returning
	return plaintext, nil
}

// verifyMagic ensures the magic string is correct and decodes version
func verifyMagic(in []byte) (version int, err error) {
	magicString := in[:magicLen/2]
	versionString := in[magicLen/2 : magicLen]

	if !bytes.Equal(magicStr, magicString) {
		return 0, ErrInvalidMagic
	}

	if v, err := strconv.ParseInt(string(versionString), 10, 32); err != nil {
		return 0, ErrInvalidVersion
	} else {
		version = int(v)
	}

	return version, nil
}

// calcBlockSize for all ciphers together
func calcBlockSize(ciphers []cipher.Block) (blockSize int) {
	for i := len(ciphers) - 1; i >= 0; i-- {
		blockSize += ciphers[i].BlockSize()
	}

	return blockSize
}

// calcKeySize for all ciphers together
func calcKeySize(suite []cipherAlg) (keySize int) {
	for _, alg := range suite {
		keySize += alg.KeySize
	}
	return keySize
}

func makeCiphers(key []byte, suite []cipherAlg) ([]cipher.Block, error) {
	var blocks []cipher.Block
	offset := 0
	for _, c := range suite {
		block, err := c.CTOR(key[offset : offset+c.KeySize])
		if err != nil {
			return nil, err
		}
		blocks = append(blocks, block)
		offset += c.KeySize
	}

	return blocks, nil
}

func cipherSuite(version int) (ciphers []cipherAlg, err error) {
	suite, ok := cipherSuites[version]
	if !ok {
		return nil, fmt.Errorf("cipher suite for version %d not found", version)
	}

	for _, c := range suite {
		ciphers = append(ciphers, algorithms[c])
	}

	return ciphers, nil
}

// deriveKey returns the same key for any given version/password/salt combination
func deriveKey(version int, password, salt []byte, ln int) ([]byte, error) {
	switch version {
	case 1:
		return scrypt.Key(password, salt, 524288 /* 2<<18 */, 8, 1, ln)
	default:
		return nil, fmt.Errorf("key derivation algorithm for version %d unknown", version)
	}
}
