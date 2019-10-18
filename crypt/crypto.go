package crypt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"strconv"

	"github.com/enceve/crypto/camellia"
	"golang.org/x/crypto/cast5"
)

// Error returns from decoding
var (
	ErrInvalidMagic    = errors.New("invalid magic string")
	ErrWrongPassphrase = errors.New("incorrect passphrase")
	ErrInvalidVersion  = errors.New("invalid version")
	ErrInvalidKey      = errors.New("key size is wrong for the cipher suite")
	ErrInvalidSalt     = errors.New("salt size is wrong")
)

const (
	magicLen = 16
	magicStr = "blobpass"

	maxVersion = 99999999
)

// v0Header is a special case
var v0Header = []byte{
	0x6b, 0x6e, 0x69, 0x6f, 0x70, 0x61, 0x73, 0x73,
	0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x31,
}

// config represents a configuration for the encryption/decryption/keygen
// behavior.
type config struct {
	version   int
	algs      []string
	saltSize  int
	keySize   int
	blockSize int

	// these functions must be set for the config to be able to do anything
	encrypt encryptFn
	decrypt decryptFn
	keygen  keyFn
}

type cipherAlg struct {
	KeySize   int
	BlockSize int
	CTOR      func(key []byte) (cipher.Block, error)
}

// These are the functions that each config needs to have. It is not
// implemented as an interface since it's more of a configuration than a
// separate type that needs to implement anything specific and different
// versions/configs can easily borrow implementations from others.
type (
	encryptFn func(c config, key, salt, pt []byte) (encrypted []byte, err error)
	decryptFn func(c config, passphrase, encrypted []byte) (pt, key, salt []byte, err error)
	keyFn     func(c config, passphrase, salt []byte) (key []byte, err error)
)

var (
	algorithms = map[string]cipherAlg{
		"AES":      {KeySize: 32, BlockSize: aes.BlockSize, CTOR: aes.NewCipher},
		"Camellia": {KeySize: 32, BlockSize: camellia.BlockSize, CTOR: camellia.NewCipher},
		"CAST5":    {KeySize: 16, BlockSize: cast5.BlockSize, CTOR: func(key []byte) (cipher.Block, error) { return cast5.NewCipher(key) }},
	}
	versions = make(map[int]config)
)

func init() {
	// Create all the versioned configurations
	makeVersion(1, encryptV1, decryptV1, deriveKeyV1, 32, "AES", "Camellia", "CAST5")
}

// makeVersion is a helper for calculating block and key size from the
// constant list of algorithms and putting the entry in versions
func makeVersion(version int, e encryptFn, d decryptFn, k keyFn, saltSize int, algs ...string) config {
	c := config{
		version:  version,
		saltSize: saltSize,
		encrypt:  e,
		decrypt:  d,
		keygen:   k,
	}

	for _, a := range algs {
		alg, ok := algorithms[a]
		if !ok {
			panic(fmt.Sprintf("unknown algorithm %s", a))
		}
		c.algs = append(c.algs, a)
		c.keySize += alg.KeySize
		c.blockSize += alg.BlockSize
	}

	versions[version] = c
	return c
}

// Encrypt data. The version corresponds to which cipher suite is used and
// therefore what length of key is needed. Which is why it's important to
// use the same version between DeriveKey and this.
//
// It's intended that this method is called with either the same parameters
// that were returned from Decrypt() (key, salt) to re-use the same key and salt
// therefore avoid a rekey operation which is costly, or to call DeriveKey
// to get a new key and salt whether attempting to rekey or simply creating
// a new encrypted file for which Decrypt() cannot be called.
//
// It can be possible that a rekey is needed due to version mismatch issues. In
// this case ErrInvalidKey/ErrInvalidSalt will signal the need to use DeriveKey
// to get a new one.
//
// In order to avoid data loss it's recommended that DeriveKey is called
// immediately after Decrypt in case that DeriveKey fails for resource usage
// reasons instead of after a user has performed edits etc.
func Encrypt(version int, key, salt, plaintext []byte) (encrypted []byte, err error) {
	c, err := getVersion(version)
	if err != nil {
		return nil, err
	}

	return c.encrypt(c, key, salt, plaintext)
}

// DecryptMeta holds things that are not the plain text, but can be useful
// for key-reuse or knowing when we should re-use key.
type DecryptMeta struct {
	Version int
	Key     []byte
	Salt    []byte
}

// Decrypt data, requires the full input (all headers) returned from Encrypt
// It returns some decryption meta pieces (version, key, salt) for use with
// Encrypt, as well as the plain text.
func Decrypt(passphrase, encrypted []byte) (meta DecryptMeta, pt []byte, err error) {
	if bytes.Equal(v0Header, encrypted[:len(v0Header)]) {
		pt, key, salt, err := decryptV0(passphrase, encrypted)
		if err != nil {
			return meta, nil, err
		}

		return DecryptMeta{Version: 0, Key: key, Salt: salt}, pt, err
	}

	version, err := verifyMagic(encrypted)
	if err != nil {
		return meta, nil, err
	}

	c, err := getVersion(version)
	if err != nil {
		return meta, nil, fmt.Errorf("unknown version %d, try upgrading bpass", version)
	}

	pt, key, salt, err := c.decrypt(c, passphrase, encrypted)
	if err != nil {
		return meta, nil, err
	}

	return DecryptMeta{Version: version, Key: key, Salt: salt}, pt, nil
}

// DeriveKey from a passphrase. It returns both the key that was derived and
// the salt used to create it.
func DeriveKey(version int, passphrase []byte) (key, salt []byte, err error) {
	c, err := getVersion(version)
	if err != nil {
		return nil, nil, err
	}

	// Secure random salt for passphrase derivation
	salt = make([]byte, c.saltSize)
	if n, err := rand.Read(salt); n != c.saltSize || err != nil {
		return nil, nil, fmt.Errorf("failed to get randomness for salt: %w", err)
	}

	key, err = c.keygen(c, passphrase, salt)
	if err != nil {
		return nil, nil, err
	}

	return key, salt, nil
}

func getVersion(version int) (c config, err error) {
	config, ok := versions[version]
	if !ok {
		return config, fmt.Errorf("unknown version %d", version)
	}

	return config, nil
}

// verifyMagic ensures the magic string is correct and decodes version
func verifyMagic(in []byte) (version int, err error) {
	magicString := in[:magicLen/2]
	versionString := in[magicLen/2 : magicLen]

	if !bytes.Equal([]byte(magicStr), magicString) {
		return 0, ErrInvalidMagic
	}

	v, err := strconv.ParseInt(string(versionString), 10, 32)
	if err != nil {
		return 0, ErrInvalidVersion
	}

	version = int(v)
	return version, nil
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

func cipherSuite(c config) (ciphers []cipherAlg, err error) {
	for _, a := range c.algs {
		alg, ok := algorithms[a]
		if !ok {
			return nil, fmt.Errorf("algorithm not found: %s", a)
		}
		ciphers = append(ciphers, alg)
	}

	return ciphers, nil
}
