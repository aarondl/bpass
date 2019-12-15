package crypt

import (
	"crypto/sha256"
	"errors"
	"fmt"
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

// validate the encryption params for encrypting
func (p Params) validate(c config) error {
	if len(p.Keys) == 0 {
		return errors.New("must have at least one key")
	}
	if len(p.Salts) == 0 {
		return errors.New("must have at least one salt")
	}
	for i, key := range p.Keys {
		if len(key) != 0 && len(key) != c.keySize {
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

	if len(p.Keys) != p.NUsers {
		return errors.New("each user must have a key")
	}
	if len(p.Salts) != p.NUsers {
		return errors.New("each user must have a salt")
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
		if len(iv) != c.blockSize {
			return fmt.Errorf("ivs[%d] must be %d bytes", i, c.blockSize)
		}
	}
	if len(p.MKeys) != p.NUsers {
		return errors.New("mkeys must be the same length as nusers")
	}
	for i, mkey := range p.MKeys {
		if len(mkey) != c.keySize {
			return fmt.Errorf("mkeys[%d] must be %d bytes", i, c.keySize)
		}
	}

	if p.IVM != nil && len(p.IVM) != c.blockSize {
		return fmt.Errorf("ivm must be %d bytes", c.blockSize)
	}
	if p.Master != nil && len(p.Master) != c.keySize {
		return fmt.Errorf("master key must be %d bytes", c.keySize)
	}

	return nil
}
