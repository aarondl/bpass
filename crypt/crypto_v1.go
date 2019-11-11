package crypt

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"io"
	"strconv"

	"github.com/aarondl/bpass/pkcs7"
	"golang.org/x/crypto/scrypt"
)

// newMasterKeyV1 generates a multi-user master key and iv
func newMasterKeyV1(c config) (master, ivm []byte, err error) {
	master = make([]byte, c.keySize)
	if _, err := io.ReadFull(rand.Reader, master); err != nil {
		return nil, nil, err
	}
	ivm = make([]byte, c.blockSize)
	if _, err := io.ReadFull(rand.Reader, ivm); err != nil {
		return nil, nil, err
	}

	return master, ivm, nil
}

// encryptV1 creates this format:
// 8:magic|4:version|4:0|32:passphraseSalt|blockSize:iv|(64:sha512|data)
// or in the multi-user case:
// 8:magic|4:version|4:nusers|32:u1|32:s1|32:iv1|80:(mk)|32:u2|32:s2|32:iv2|80:(mk)|32:ivm|(sha|pt)
// where the sha512 covers all fields except itself
func encryptV1(c config, p *Params, plaintext []byte) (encrypted []byte, err error) {
	if p.NUsers == 0 {
		return encryptV1Single(c, p, plaintext)
	}
	return encryptV1Multi(c, p, plaintext)
}

func encryptV1Single(c config, p *Params, plaintext []byte) (encrypted []byte, err error) {
	cipherSuite, err := cipherSuite(c)
	if err != nil {
		return nil, err
	}

	if len(p.Keys[0]) != c.keySize {
		return nil, ErrInvalidKey
	}

	if len(p.Salts[0]) != c.saltSize {
		return nil, ErrInvalidSalt
	}

	ciphers, err := makeCiphers(p.Keys[0], cipherSuite)
	if err != nil {
		return nil, err
	}

	// Create an iv for all ciphers at once
	iv := make([]byte, c.blockSize)
	if n, err := rand.Read(iv); n != c.blockSize || err != nil {
		return nil, fmt.Errorf("failed to get randomness for iv: %w", err)
	}

	plaintextHeader := make([]byte, magicLen+c.saltSize+c.blockSize)
	copy(plaintextHeader, fmt.Sprintf("%s%04d%04d", magicStr, c.version, 0))
	copy(plaintextHeader[magicLen:], p.Salts[0])
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

func encryptV1Multi(c config, p *Params, plaintext []byte) (encrypted []byte, err error) {
	cipherSuite, err := cipherSuite(c)
	if err != nil {
		return nil, err
	}

	userSize := sha256.Size + c.saltSize + c.blockSize + c.keySize
	plaintextHeader := make([]byte,
		magicLen+(userSize*p.NUsers)+c.blockSize,
	)
	copy(plaintextHeader, fmt.Sprintf("%s%04d%04d", magicStr, c.version, p.NUsers))

	// Copy all user data into the plaintext header
	offset := magicLen
	for i := 0; i < p.NUsers; i++ {
		key := p.Keys[i]
		if len(key) != 0 && len(key) != c.keySize {
			return nil, ErrInvalidKey
		}
		if len(p.Salts[i]) != c.saltSize {
			return nil, ErrInvalidSalt
		}

		// These should always be here
		copy(plaintextHeader[offset:], p.Users[i])
		offset += sha256.Size
		copy(plaintextHeader[offset:], p.Salts[i])
		offset += c.saltSize
		copy(plaintextHeader[offset:], p.IVs[i])
		offset += c.blockSize
		copy(plaintextHeader[offset:], p.MKeys[i])
		offset += c.keySize
	}

	copy(plaintextHeader[offset:], p.IVM)

	ciphers, err := makeCiphers(p.Master, cipherSuite)
	if err != nil {
		return nil, err
	}

	// Plain text header is complete, encrypt payload
	sha := sha512.New()
	_, _ = sha.Write(plaintextHeader)
	_, _ = sha.Write(plaintext)
	shaSum := sha.Sum(nil)

	work := make([]byte, sha512.Size+len(plaintext))
	copy(work, shaSum)
	copy(work[sha512.Size:], plaintext)

	ivOffset := 0
	iv := p.IVM
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

func encryptMasterKeyV1(c config, userKey []byte, master []byte) (cryptedMaster, iv []byte, err error) {
	if len(master) != c.keySize {
		return nil, nil, errors.New("master key wrong size")
	}
	if len(userKey) != c.keySize {
		return nil, nil, errors.New("user key size wrong")
	}

	cryptedMaster = make([]byte, len(master))
	copy(cryptedMaster, master)

	cipherSuite, err := cipherSuite(c)
	if err != nil {
		return nil, nil, err
	}

	ciphers, err := makeCiphers(userKey, cipherSuite)
	if err != nil {
		return nil, nil, err
	}

	iv = make([]byte, c.blockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, nil, fmt.Errorf("error generating randomness for iv: %w", err)
	}

	ivOffset := 0
	for i, c := range ciphers {
		cipherBlockSize := cipherSuite[i].BlockSize

		// Pull out blockSize iv bytes for our cipher
		cbc := cipher.NewCBCEncrypter(c, iv[ivOffset:ivOffset+cipherBlockSize])
		ivOffset += cipherBlockSize

		// encrypt
		cbc.CryptBlocks(cryptedMaster, cryptedMaster)
	}

	return cryptedMaster, iv, nil
}

func decryptV1(c config, user, passphrase, key, salt, encrypted []byte) (p Params, plaintext []byte, err error) {
	nUserBytes := encrypted[12:16]

	var nUsers int
	i, err := strconv.ParseInt(string(nUserBytes), 10, 32)
	if err != nil {
		return p, nil, ErrInvalidFileFormat
	}

	nUsers = int(i)
	if nUsers != 0 && len(user) == 0 {
		return p, nil, ErrNeedUser
	}

	if nUsers == 0 {
		return decryptV1Single(c, passphrase, key, salt, encrypted)
	}
	return decryptV1Multi(c, nUsers, user, passphrase, key, salt, encrypted)
}

func decryptV1Single(c config, passphrase, key, salt, encrypted []byte) (p Params, plaintext []byte, err error) {
	suite, err := cipherSuite(c)
	if err != nil {
		return p, nil, err
	}

	// Pull salt out and derive key
	newSalt := encrypted[magicLen : magicLen+c.saltSize]
	doDerive := !bytes.Equal(salt, newSalt)

	if key == nil || doDerive {
		if len(passphrase) == 0 {
			return p, nil, ErrWrongPassphrase
		}

		salt = newSalt
		key, err = c.keygen(c, passphrase, salt)
		if err != nil {
			return p, nil, err
		}
	}

	ciphers, err := makeCiphers(key, suite)
	if err != nil {
		return p, nil, err
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
			return p, nil, ErrWrongPassphrase
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
		return p, nil, ErrWrongPassphrase
	}

	if len(p.Keys) == 0 {
		p.Keys = [][]byte{nil}
	}
	if len(p.Salts) == 0 {
		p.Salts = [][]byte{nil}
	}
	if len(p.IVs) == 0 {
		p.IVs = [][]byte{nil}
	}
	p.Keys[0] = key
	p.Salts[0] = salt
	p.IVs[0] = iv
	return p, plaintext, nil
}

func decryptV1Multi(c config, nUsers int, user, passphrase, key, salt, encrypted []byte) (p Params, plaintext []byte, err error) {
	p.NUsers = nUsers
	p.User = -1

	s := sha256.Sum256(user)
	userHash := s[:]

	plaintextHeader := encrypted[magicLen:]

	for i := 0; i < nUsers; i++ {
		p.Users = append(p.Users, make([]byte, sha256.Size))
		copy(p.Users[i], plaintextHeader[:sha256.Size])
		plaintextHeader = plaintextHeader[sha256.Size:]

		if p.User < 0 && bytes.Equal(p.Users[i], userHash) {
			p.User = i
		}

		p.Salts = append(p.Salts, make([]byte, c.saltSize))
		copy(p.Salts[i], plaintextHeader[:c.saltSize])
		plaintextHeader = plaintextHeader[c.saltSize:]

		p.IVs = append(p.IVs, make([]byte, c.blockSize))
		copy(p.IVs[i], plaintextHeader[:c.blockSize])
		plaintextHeader = plaintextHeader[c.blockSize:]

		p.MKeys = append(p.MKeys, make([]byte, c.keySize))
		copy(p.MKeys[i], plaintextHeader[:c.keySize])
		plaintextHeader = plaintextHeader[c.keySize:]
	}

	if p.User < 0 {
		return p, nil, ErrUnknownUser
	}

	p.IVM = make([]byte, c.blockSize)
	copy(p.IVM, plaintextHeader[:c.blockSize])
	plaintextHeader = plaintextHeader[c.blockSize:]

	if len(key) == 0 || !bytes.Equal(salt, p.Salts[p.User]) {
		if len(passphrase) == 0 {
			return p, nil, ErrWrongPassphrase
		}
		// The salt was changed so the resulting key won't be the same as
		// the one that was passed in, we have to derive
		salt = p.Salts[p.User]
		key, err = c.keygen(c, passphrase, salt)
		if err != nil {
			return p, nil, err
		}
	}

	// Add our key in there
	p.Keys = make([][]byte, p.NUsers)
	p.Keys[p.User] = key
	p.Salts[p.User] = salt

	suite, err := cipherSuite(c)
	if err != nil {
		return p, nil, err
	}
	ciphers, err := makeCiphers(key, suite)
	if err != nil {
		return p, nil, err
	}

	p.Master = make([]byte, c.keySize)
	iv := p.IVs[p.User]
	ivOffset := len(iv)
	copy(p.Master, p.MKeys[p.User])
	// First decode the master key with our chosen user
	for i := len(ciphers) - 1; i >= 0; i-- {
		c := ciphers[i]

		cipherBlockSize := c.BlockSize()
		cbc := cipher.NewCBCDecrypter(c, iv[ivOffset-cipherBlockSize:ivOffset])
		ivOffset -= cipherBlockSize

		cbc.CryptBlocks(p.Master, p.Master)
	}

	// Use the decrypted master key to instantiate the cipher suite
	ciphers, err = makeCiphers(p.Master, suite)
	if err != nil {
		return p, nil, err
	}

	// Copy the ciphertext (remainder of plaintextHeader) to where we can
	// decode it
	ciphertext := make([]byte, len(plaintextHeader))
	copy(ciphertext, plaintextHeader)

	iv = p.IVM
	ivOffset = len(iv)
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
			return p, nil, ErrWrongPassphrase
		}
	}

	userSize := sha256.Size + c.saltSize + c.blockSize + c.keySize
	oldHash := ciphertext[:sha512.Size]
	plaintext = ciphertext[sha512.Size:]

	newHash := sha512.New()
	_, _ = newHash.Write(encrypted[:magicLen+(userSize*p.NUsers)+c.blockSize])
	_, _ = newHash.Write(plaintext)
	shaSum := newHash.Sum(nil)

	if !bytes.Equal(shaSum, oldHash) {
		return p, nil, ErrWrongPassphrase
	}

	return p, plaintext, nil
}

func deriveKeyV1(c config, passphrase, salt []byte) ([]byte, error) {
	return scrypt.Key(passphrase, salt, 524288 /* 2<<18 */, 8, 1, c.keySize)
}
