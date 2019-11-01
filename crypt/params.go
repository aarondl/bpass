package crypt

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
)

// Params for encryption.
//
// For encryption for a single user the following must be provided:
// Key, Salt
//
// For encryption for multiple users all fields must be provided.
type Params struct {
	// This version is stored by Decrypt() so we know if we're
	// encrypting the same version or not.
	version int

	// Users is how many users exist where User is which user is selected
	// In a single-user file all of these will be 0
	NUsers int
	// User is the active user and the index
	// into the fields used for Salts/IVs/MKeys to perform encryptions with.
	User int

	// Keys are the user's keys (DeriveKey(password, Salts[User]))
	Keys [][]byte
	// Salts for all users
	Salts [][]byte

	// The following fields are nil when NUsers = 0
	// Users is the sha256 of all the usernames in the file
	Users [][]byte
	// IVs for all users (to decrypt master keys). If an IV is nil it will
	// be generated.
	IVs [][]byte
	// MKeys for all users (encrypted master key blobs). If entries
	// are nil then the key/iv will be attempt to be used to encrypt master
	// with it.
	MKeys [][]byte

	// These fields are also nil when NUsers = 0
	// IVM is the iv for decoding the master key
	// If IVM is nil, it will be generated, this requires a complete redo
	// of MKeys and thus requires all Keys and all IVs for all users.
	IVM []byte
	// Master is the master key, decrypted from one of the master key blocks
	// If the master key is nil, it will be generated.
	Master []byte
}

// SetSingleUser sets up the params to be a single user encryption scheme
// using the key and salt (usually created by DeriveKey)
func (p *Params) SetSingleUser(key, salt []byte) {
	p.Keys = [][]byte{key}
	p.Salts = [][]byte{salt}

	p.NUsers, p.User = 0, 0
	p.Users, p.IVs, p.MKeys, p.IVM, p.Master = nil, nil, nil, nil, nil
}

// AddUser adds a user to the parameters. Key and Salt may be created
// using DeriveKey. If the current file is not a multi-user file, this simply
// changes it into one.
//
// Keys[0],Salt[0] may be passed in to avoid another call to DeriveKey
// in this case.
//
// Returns an error if the user name has already been used
func (p *Params) AddUser(username string, key, salt []byte) error {
	if p.NUsers == 0 {
		// Wipe out the single user parameters
		p.Keys = nil
		p.Salts = nil
		p.IVs = nil
	}

	sum := sha256.Sum256([]byte(username))
	hash := sum[:]

	for _, u := range p.Users {
		if bytes.Equal(u, hash) {
			return errors.New("user already added")
		}
	}

	p.Users = append(p.Users, hash)
	p.Keys = append(p.Keys, key)
	p.Salts = append(p.Salts, salt)
	p.IVs = append(p.IVs, nil)     // force generation
	p.MKeys = append(p.MKeys, nil) // force generation

	p.NUsers++
	return nil
}

// RemoveUser from the parameters.
//
// Returns ErrUnknownUser if user is not found.
//
// If the user is the last user, it will remove him and convert the file
// to a single user file.
//
// If the user to-be-removed user is not the last one and
// was the one to open the file, it will return an error to prevent the user
// from locking himself out, he must be removed by a different user.
func (p *Params) RemoveUser(username string) error {
	sum := sha256.Sum256([]byte(username))
	index := -1
	for i, u := range p.Users {
		if bytes.Equal(sum[:], u) {
			index = i
			break
		}
	}

	if index < 0 {
		return ErrUnknownUser
	}

	if p.NUsers == 1 {
		p.SetSingleUser(p.Keys[0], p.Salts[0])
		return nil
	}

	if p.User == index {
		return errors.New("cannot remove user who opened the file unless they are the last")
	}

	// Keep the ordering, delete from each slice
	copy(p.Keys[index:], p.Keys[index+1:])
	p.Keys = p.Keys[:len(p.Keys)-1]

	copy(p.Salts[index:], p.Salts[index+1:])
	p.Salts = p.Salts[:len(p.Salts)-1]

	copy(p.Users[index:], p.Users[index+1:])
	p.Users = p.Users[:len(p.Users)-1]

	copy(p.IVs[index:], p.IVs[index+1:])
	p.IVs = p.IVs[:len(p.IVs)-1]

	copy(p.MKeys[index:], p.MKeys[index+1:])
	p.MKeys = p.MKeys[:len(p.MKeys)-1]

	return nil
}

// Rekey rekeys the user who opened the file
func (p *Params) Rekey(key, salt []byte) {
	p.rekeyIndex(key, salt, p.User)
}

// RekeyUser by name. Return ErrUnknownUser if the user is not found.
func (p *Params) RekeyUser(username string, key, salt []byte) error {
	sum := sha256.Sum256([]byte(username))
	index := -1
	for i, u := range p.Users {
		if bytes.Equal(sum[:], u) {
			index = i
			break
		}
	}

	if index < 0 {
		return ErrUnknownUser
	}

	p.rekeyIndex(key, salt, index)
	return nil
}

// RekeyAll is a massively destructive operation that will delete everybody's
// current keys, generate new passwords for them, derive those into keys
// and set them. This process is extremely expensive.
//
// Consequently it's impossible for us to know (thanks hashing) who these
// passwords belong to, I hope you remember the order of the people who
// are in the file!
func (p *Params) RekeyAll(version int) ([]string, error) {
	if p.NUsers == 0 {
		pwd, err := getRandomPassphrase()
		if err != nil {
			return nil, err
		}

		key, salt, err := DeriveKey(version, pwd)
		if err != nil {
			return nil, err
		}
		p.SetSingleUser(key, salt)
		return []string{string(pwd)}, nil
	}

	passwords := make([]string, p.NUsers)

	for i := 0; i < p.NUsers; i++ {
		pwd, err := getRandomPassphrase()
		if err != nil {
			return nil, err
		}

		key, salt, err := DeriveKey(version, pwd)
		if err != nil {
			return nil, err
		}

		passwords[i] = string(pwd)

		p.Keys[i] = key
		p.Salts[i] = salt
		p.IVs[i] = nil
		p.MKeys[i] = nil
	}
	p.IVM = nil
	p.Master = nil

	return passwords, nil
}

var alphabet = `abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789`

func getRandomPassphrase() ([]byte, error) {
	b := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, err
	}

	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}

	return b, nil
}

func (p *Params) rekeyIndex(key, salt []byte, index int) {
	p.Keys[index] = key
	p.Salts[index] = salt

	if p.NUsers == 0 {
		return
	}

	// Force regeneration
	p.IVs[index] = nil
	p.MKeys[index] = nil
}

// validate the encryption params for encrypting
func (p Params) validate(c config) error {
	if len(p.Keys) == 0 {
		return errors.New("must have at least one key")
	}
	if len(p.Salts) == 0 {
		return errors.New("must have at least one salt")
	}
	for i, mkey := range p.Keys {
		if len(mkey) != c.keySize {
			return fmt.Errorf("keys[%d] must be %d bytes", i, c.keySize)
		}
	}
	for i, salt := range p.Salts {
		if len(salt) != c.saltSize {
			return fmt.Errorf("salts[%d] must be %d bytes", i, c.saltSize)
		}
	}

	if p.NUsers == 0 {
		return nil
	}

	if p.version != c.version && (len(p.Master) != 0 || len(p.IVM) != 0) {
		return ErrNeedFullRekey
	}

	if len(p.Keys) != p.NUsers {
		return errors.New("must have at least one salt")
	}
	if len(p.Salts) != p.NUsers {
		return errors.New("must have at least one salt")
	}

	if p.User < 0 || p.User >= p.NUsers {
		return errors.New("user should be an index of 0 <= user < nUsers")
	}

	if len(p.Users) != p.NUsers {
		return errors.New("users must be the same length as nusers")
	}
	for i, user := range p.Users {
		if len(user) != sha256.Size {
			return fmt.Errorf("users[%d] must be %d bytes", i, sha256.Size)
		}
	}
	if len(p.IVs) != p.NUsers {
		return errors.New("ivs must be the same length as nusers")
	}
	for i, iv := range p.IVs {
		if iv == nil {
			continue
		}
		if len(iv) != c.blockSize {
			return fmt.Errorf("ivs[%d] must be %d bytes", i, c.blockSize)
		}
	}
	if len(p.MKeys) != p.NUsers {
		return errors.New("mkeys must be the same length as nusers")
	}
	for i, mkey := range p.MKeys {
		if mkey == nil {
			continue
		}
		if len(mkey) != c.keySize {
			return fmt.Errorf("mkeys[%d] must be %d bytes", i, c.keySize)
		}
	}

	if p.IVM != nil && len(p.IVM) == c.blockSize {
		return fmt.Errorf("ivm must be %d bytes", c.blockSize)
	}
	if p.Master != nil && len(p.Master) == 0 {
		return fmt.Errorf("master key must be %d bytes", c.keySize)
	}

	return nil
}
