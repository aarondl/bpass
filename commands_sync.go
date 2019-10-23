package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math"
	"strconv"

	"github.com/aarondl/bpass/blobformat"

	"golang.org/x/crypto/ssh"
)

const (
	syncMasterKey = "sync/master"

	syncSSH = "ssh"
)

func (u *uiContext) sync() error {
	return nil
}

func (u *uiContext) syncAddInterruptible(kind string) error {
	err := u.syncAdd(kind)
	switch err {
	case nil:
		return nil
	case ErrEnd:
		errColor.Println("Aborted")
		return nil
	default:
		return err
	}
}

func (u *uiContext) syncAdd(kind string) error {
	found := false
	for _, k := range []string{syncSSH} {
		if k == kind {
			found = true
			break
		}
	}

	if !found {
		errColor.Printf("%q is not a supported sync kind (old version of bpass?)\n", kind)
		return nil
	}

	// New entry
	newEntry, err := u.store.NewSync(kind)
	if err != nil {
		return err
	}

	host, err := u.getString("host")
	if err != nil {
		return err
	}
	newEntry[blobformat.KeyHost] = host

	port := "22"
	for {
		port, err = u.prompt(inputPromptColor.Sprint("port (22): "))
		if err != nil {
			return err
		}

		if len(port) == 0 {
			break
		}

		_, err = strconv.Atoi(port)
		if err != nil {
			errColor.Printf("port must be an integer between %d and %d\n", 1, int(math.MaxUint16)-1)
			continue
		}

		break
	}
	newEntry[blobformat.KeyPort] = port

	file, err := u.getString("path")
	if err != nil {
		return err
	}
	newEntry[blobformat.KeyPath] = file

	inputPromptColor.Println("Key type:")
	choice, err := u.getMenuChoice(inputPromptColor.Sprint("> "), []string{"ED25519", "RSA 4096", "Password"})
	if err != nil {
		return err
	}

	switch choice {
	case 0:
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			errColor.Println("failed to generate ed25519 ssh key")
			return nil
		}

		// Marshal private key into DER ASN.1 then to PEM
		b, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			errColor.Println("failed to marshal ed25519 private key with x509:", err)
		}
		pemBlock := pem.Block{Type: "PRIVATE KEY", Bytes: b}
		b = pem.EncodeToMemory(&pemBlock)

		public, err := ssh.NewPublicKey(pub)
		if err != nil {
			errColor.Println("failed to parse public key:", err)
		}
		publicStr := string(bytes.TrimSpace(ssh.MarshalAuthorizedKey(public)))

		newEntry[blobformat.KeySecret] = string(bytes.TrimSpace(b))
		newEntry[blobformat.KeyPub] = publicStr

		infoColor.Printf("successfully generated new ed25519 key:\n%s\n", publicStr)

	case 1:
		priv, err := rsa.GenerateKey(rand.Reader, 4096)
		if err != nil {
			errColor.Println("failed to generate rsa-4096 ssh key")
			return nil
		}

		// Marshal private key into DER ASN.1 then to PEM
		b, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			errColor.Println("failed to marshal rsa private key with x509:", err)
			return nil
		}
		pemBlock := pem.Block{Type: "PRIVATE KEY", Bytes: b}
		b = pem.EncodeToMemory(&pemBlock)

		public, err := ssh.NewPublicKey(&priv.PublicKey)
		if err != nil {
			errColor.Println("failed to parse public key:", err)
		}
		publicStr := string(bytes.TrimSpace(ssh.MarshalAuthorizedKey(public)))

		newEntry[blobformat.KeySecret] = string(bytes.TrimSpace(b))
		newEntry[blobformat.KeyPub] = publicStr

		infoColor.Printf("successfully generated new rsa-4096 key:\n%s\n", publicStr)

	case 2:
		user, err := u.getString("user")
		if err != nil {
			return err
		}

		pass, err := u.getPassword()
		if err != nil {
			return err
		}

		newEntry[blobformat.KeyUser] = user
		newEntry[blobformat.KeyPass] = pass
	default:
		panic("how did this happen?")
	}

	if err = u.store.Add(newEntry); err != nil {
		return err
	}
	if err = u.store.AddSync(newEntry.UUID()); err != nil {
		return err
	}

	fmt.Println()
	infoColor.Println("Added new sync:", newEntry.Name())

	return nil
}

func (u *uiContext) syncRemove(name string) error {
	uuid, _ := u.store.Find(name)
	if len(uuid) == 0 {
		errColor.Printf("could not find %s\n", name)
		return nil
	}

	if _, err := u.store.RemoveSync(uuid); err != nil {
		return err
	}

	infoColor.Printf("removed %q from sync (use rm to delete entry)\n", name)
	return nil
}

func (u *uiContext) findSyncMaster() (string, blobformat.Blob) {
	for uuid, blobIntf := range u.store {
		blob := blobformat.Blob(blobIntf.(map[string]interface{}))

		if blob.Name() == syncMasterKey {
			return uuid, blob
		}
	}

	return "", nil
}
