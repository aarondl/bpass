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
	ErrWrongPassphrase = errors.New("incorrect passphrase")
	ErrInvalidMagic    = errors.New("invalid magic string")
	ErrNeedUser        = errors.New("need user")
	ErrUnknownUser     = errors.New("unknown user")
	ErrInvalidVersion  = errors.New("invalid version")
)

// Error returns from encoding
var (
	ErrNeedFullRekey = errors.New("full rekey is required to complete this operation")
	ErrInvalidKey    = errors.New("key size is wrong for the cipher suite")
	ErrInvalidSalt   = errors.New("salt size is wrong")
)

const (
	magicLen = 16
	magicStr = "blobpass"

	maxVersion = 9999
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
	encryptFn func(c config, p *Params, pt []byte) (encrypted []byte, err error)
	decryptFn func(c config, user, passphrase, key, salt, encrypted []byte) (p Params, pt []byte, err error)
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
// that were returned from Decrypt(), this is especially important in multi-user
// files since the old pieces of data must be put back verbatim.
//
// It can be possible that a rekey is needed due to version mismatch issues. In
// this case ErrInvalidKey/ErrInvalidSalt will signal the need to use DeriveKey
// to get a new one.
//
// In multi-user files if there is a version mismatch it is impossible
// to migrate to the next version without a full rekey so ErrNeedFullRekey
// will be returned. The same is true if params does not include Master/IVM
// as all users are required to encrypt the Master key with theirs
// and the payload must be encrypted with Master+IVM so either one missing
// prompts ErrNeedFullRekey if there are user keys missing.
func Encrypt(version int, p *Params, plaintext []byte) (encrypted []byte, err error) {
	c, err := getVersion(version)
	if err != nil {
		return nil, err
	}

	if err = p.validate(c); err != nil {
		return nil, fmt.Errorf("params were invalid: %w", err)
	}

	return c.encrypt(c, p, plaintext)
}

// Decrypt data, requires the full input (all headers) returned from Encrypt
// It returns some parameters that can be used to encrypt data with.
//
// If a key contains keys that can be used to decrypt without deriving
// a key from passphrase they will be used instead. If decryption fails
// and no passphrase has been provided to derive with, ErrWrongPassphrase
// will be returned.
//
// If user is nil but the file is a multi-user file then ErrNeedUser
// will be returned. If the user was specified but was not found in the file
// then ErrUnknownUser is returned.
func Decrypt(user, passphrase, key, salt, encrypted []byte) (version int, p Params, pt []byte, err error) {
	if bytes.Equal(v0Header, encrypted[:len(v0Header)]) {
		pt, key, salt, err := decryptV0(passphrase, encrypted)
		if err != nil {
			return 0, p, nil, err
		}

		return 0, Params{Keys: [][]byte{key}, Salts: [][]byte{salt}}, pt, err
	}

	version, err = verifyMagic(encrypted)
	if err != nil {
		return 0, p, nil, err
	}

	c, err := getVersion(version)
	if err != nil {
		return 0, p, nil, fmt.Errorf("unknown version %d, try upgrading bpass", version)
	}

	p, pt, err = c.decrypt(c, user, passphrase, key, salt, encrypted)
	if err != nil {
		return 0, p, nil, err
	}

	// Tag the params with the version we found for later
	p.version = version
	return version, p, pt, nil
}

// DeriveKey from a passphrase. It returns both the key that was derived and
// the salt used to create it.
//
// DeriveKey uses cpu and memory hard algorithms, this is very taxing on the
// computer on which its run and so if a rekey is necessary it should
// probably occur after a save, or early in the lifecycle due to the
// likelihood of crashing the program given the high resource usages.
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
	in = in[magicLen/2:]
	versionString := in[:magicLen/4]

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
