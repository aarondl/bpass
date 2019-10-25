package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/aarondl/bpass/crypt"
	"github.com/aarondl/bpass/scpsync"
	"github.com/aarondl/bpass/txblob"
	"github.com/aarondl/bpass/txformat"

	"golang.org/x/crypto/ssh"
)

const (
	syncMasterKey = "sync/master"

	syncSSH = "ssh"
)

func (u *uiContext) sync(auto, push bool) error {
	master, masterBlob, err := u.store.Find(syncMasterKey)
	if err != nil {
		return err
	}
	if len(master) == 0 {
		if !auto {
			infoColor.Println("No sync accounts created (see: sync add)")
		}
		return nil
	}

	syncs, err := masterBlob.Sync()
	if err != nil {
		return err
	}
	if len(master) == 0 {
		if !auto {
			infoColor.Println("No sync accounts created (see: sync add)")
		}
		return nil
	}

	// From here on we need to avoid updating the store snapshot until we're
	// done syncing all the accounts, otherwise we run the risk of downloading
	// a new sync account halfway through and that's just weird.

	var validSyncs []string

	for _, s := range syncs {
		uuid := s.Value

		entry, ok := u.store.Snapshot[uuid]
		if !ok {
			errColor.Printf("entry %q was set up as sync account, but no longer exists and will be removed\n", uuid)
			if err := u.store.Store.DeleteList(master, txblob.KeySync, s.UUID); err != nil {
				return err
			}
			continue
		}

		name, _ := entry.String(txblob.KeyName)

		// We ignore the error here, it will either be a wrong type which
		kind, err := entry.String(txblob.KeySyncKind)
		if err != nil {
			if txformat.IsKeyNotFound(err) {
				errColor.Printf("entry %q is a sync account but had no %q key\n", name, txblob.KeySyncKind)
				continue
			} else {
				errColor.Println(err)
				continue
			}
		}

		switch kind {
		case syncSSH:
			validSyncs = append(validSyncs, uuid)
		default:
			errColor.Printf("entry %q is a %q sync account, but it's kind is unknown (old bpass version?)\n", name, kind)
		}
	}

	newHosts := make(map[string]string)
	var fetchedLogs [][]txformat.Tx
	var pt, ct []byte
	var log []txformat.Tx

Syncs:
	for _, uuid := range validSyncs {
		entry := u.store.Snapshot[uuid]
		name, _ := entry.String(txblob.KeyName)
		path, _ := entry.String(txblob.KeyPath)
		kind := entry[txblob.KeySyncKind].(string)

		infoColor.Println("pulling:", name)

		switch kind {
		case syncSSH:
			var hostentry string
			hostentry, ct, err = u.sshPull(entry)

			if err != nil {
				if scpsync.IsNotFoundErr(err) {
					infoColor.Println(name, "did not have the file, skipping")
					err = nil
					continue
				}
			}

			if len(hostentry) != 0 {
				newHosts[uuid] = hostentry
			}
		}

		if err != nil {
			errColor.Printf("failed sync pull %q: %v\n", name, err)
			continue
		}

		pass := u.pass
		for {
			infoColor.Println("decrypting:", name)

			// Decrypt payload with our loaded key
			_, pt, err = crypt.Decrypt([]byte(pass), ct)
			if err == nil {
				break
			}

			if err == crypt.ErrWrongPassphrase {
				pass, err = u.prompt(inputPromptColor.Sprintf("[%s] %s passphrase: ", name, path))

				if err != nil || len(pass) == 0 {
					infoColor.Println("Skipping")
					break
				}
			} else {
				errColor.Printf("failed decrypt %q: %v\n", name, err)
				continue Syncs
			}
		}

		log, err = txformat.NewLog(pt)
		if err != nil {
			return err
		}

		fetchedLogs = append(fetchedLogs, log)
	}

	infoColor.Println("merging fetched logs")

	var c []txformat.Tx
	var conflicts []txformat.Conflict
	for _, log := range fetchedLogs {
		c, conflicts = txformat.Merge(u.store.Log, log, conflicts)

		if len(conflicts) == 0 {
			u.store.Log = c
			break
		}

		infoColor.Println(len(conflicts), " conflicts occurred during syncing!")

		for i, c := range conflicts {
			infoColor.Printf("entry %q was deleted at: %s\nbut at %s, ",
				c.DeleteTx.UUID,
				time.Unix(0, c.DeleteTx.Time).Format(time.RFC3339),
				time.Unix(0, c.SetTx.Time).Format(time.RFC3339),
			)

			switch c.SetTx.Kind {
			case txformat.TxSet:
				infoColor.Printf("a kv set happened:\n%s = %s\n",
					c.SetTx.Key,
					c.SetTx.Value,
				)
			case txformat.TxAddList:
				infoColor.Printf("a list append happened:\n%s += %s\n",
					c.SetTx.Key,
					c.SetTx.Value,
				)
			case txformat.TxDeleteKey:
				infoColor.Printf("a key delete happened for key:\n%s\n",
					c.SetTx.Key,
				)
			case txformat.TxDeleteList:
				infoColor.Printf("a list delete happened on keys:\n%s:%s\n",
					c.SetTx.Key,
					c.SetTx.Index,
				)
			}

			for {
				line, err := u.prompt("[R]estore item? [D]elete item? (r/R/d/D): ")
				if err != nil {
					return err
				}

				switch line {
				case "R", "r":
					conflicts[i].Restore()
				case "D", "d":
					conflicts[i].Delete()
				default:
					continue
				}
			}
		}
	}

	for uuid, hostentry := range newHosts {
		if _, err = u.store.Store.Append(uuid, txblob.KeyKnownHosts, hostentry); err != nil {
			return fmt.Errorf("failed to append new host entry: %w", err)
		}
	}

	if err = u.store.UpdateSnapshot(); err != nil {
		return fmt.Errorf("poisoned by our syncing friends: %w", err)
	}

	// We have all of our friends stuff, attempt to create a package to send
	// them
	if !push {
		return nil
	}

	infoColor.Println("pushing merged")

	if pt, err = u.store.Save(); err != nil {
		return err
	}

	if ct, err = crypt.Encrypt(cryptVersion, u.key, u.salt, pt); err != nil {
		return err
	}

	newHosts = make(map[string]string)
	for _, uuid := range validSyncs {
		entry := u.store.Snapshot[uuid]
		name, _ := entry.String(txblob.KeyName)
		kind := entry[txblob.KeySyncKind].(string)

		infoColor.Println("pushing:", name)

		switch kind {
		case syncSSH:
			var hostentry string
			hostentry, err = u.sshPush(entry, ct)
			if len(hostentry) != 0 {
				newHosts[uuid] = hostentry
			}
		}

		if err != nil {
			name, _ := entry.String(txblob.KeyName)
			errColor.Printf("failed syncing %q: %v\n", name, err)
			continue
		}
	}

	for uuid, hostentry := range newHosts {
		if _, err = u.store.Store.Append(uuid, txblob.KeyKnownHosts, hostentry); err != nil {
			return fmt.Errorf("failed to append new host entry: %w", err)
		}
	}

	return nil
}

func (u *uiContext) sshPull(entry txformat.Entry) (hostentry string, ct []byte, err error) {
	address, path, config, err := sshConfig(entry)
	if err != nil {
		return "", nil, err
	}

	known, err := entry.List(txblob.KeyKnownHosts)
	if err != nil {
		if !txformat.IsKeyNotFound(err) {
			return "", nil, err
		}
	}

	asker := &hostAsker{u: u, known: known}
	config.HostKeyCallback = asker.callback

	payload, err := scpsync.Recv(address, config, path)
	if err != nil {
		return "", nil, err
	}

	return asker.newHost, payload, nil
}

func (u *uiContext) sshPush(entry txformat.Entry, payload []byte) (hostentry string, err error) {
	address, path, config, err := sshConfig(entry)
	if err != nil {
		return "", err
	}

	known, err := entry.List(txblob.KeyKnownHosts)
	if err != nil {
		if !txformat.IsKeyNotFound(err) {
			return "", err
		}
	}

	asker := &hostAsker{u: u, known: known}
	config.HostKeyCallback = asker.callback

	err = scpsync.Send(address, config, path, 0600, payload)
	if err != nil {
		return "", err
	}

	return asker.newHost, nil
}

func sshConfig(entry txformat.Entry) (address, path string, config *ssh.ClientConfig, err error) {
	host, _ := entry.String(txblob.KeyHost)
	port, _ := entry.String(txblob.KeyPort)
	user, _ := entry.String(txblob.KeyUser)
	pass, _ := entry.String(txblob.KeyPass)
	secretKey, _ := entry.String(txblob.KeySecret)
	path, _ = entry.String(txblob.KeyPath)

	if len(user) == 0 {
		return "", "", nil, errors.New("missing user key")
	}
	if len(host) == 0 {
		return "", "", nil, errors.New("missing host key")
	}
	if len(port) == 0 {
		return "", "", nil, errors.New("missing port key")
	}
	if len(path) == 0 {
		return "", "", nil, errors.New("missing path key")
	}

	address = net.JoinHostPort(host, port)

	config = new(ssh.ClientConfig)
	config.User = user
	if len(pass) != 0 {
		config.Auth = append(config.Auth, ssh.Password(pass))
	}

	if len(secretKey) != 0 {
		signer, err := ssh.ParsePrivateKey([]byte(secretKey))
		if err != nil {
			return "", "", nil, err
		}
		config.Auth = append(config.Auth, ssh.PublicKeys(signer))
	}

	return address, path, config, nil
}

type hostAsker struct {
	u       *uiContext
	known   []txformat.ListEntry
	newHost string
}

func (h *hostAsker) callback(hostname string, remote net.Addr, key ssh.PublicKey) error {
	// Format is `hostname address key-type key:base64`
	keyHashBytes := sha256.Sum256(key.Marshal())
	keyHash := fmt.Sprintf("%x", keyHashBytes)

	keyType := key.Type()
	addr := remote.String()
	hostLine := fmt.Sprintf(`%s %s %s %s`, hostname, addr, keyType, keyHash)

	for _, h := range h.known {
		vals := strings.Split(h.Value, " ")

		if vals[0] != hostname {
			continue
		}

		// Same host, double check key is same
		if vals[2] != keyType {
			return errors.New("known host's key type has changed, could be a mitm attack")
		}
		if vals[3] != keyHash {
			return errors.New("known host's key has changed, could be a mitm attack")
		}

		// We've seen this host before and everything is OK
		return nil
	}

	var b strings.Builder
	for i := 0; i < len(keyHash)-1; i += 2 {
		if i != 0 {
			b.WriteByte(':')
		}
		b.WriteByte(keyHash[i])
		b.WriteByte(keyHash[i+1])
	}
	sha256FingerPrint := b.String()

	infoColor.Printf("(ssh) connected to: %s (%s)\nverify pubkey: %s %s\n",
		hostname, addr, keyType, sha256FingerPrint)
	line, err := h.u.prompt(inputPromptColor.Sprint("Save this host (y/N): "))
	if err != nil {
		return fmt.Errorf("failed to get user confirmation on host: %w", err)
	}

	switch line {
	case "y", "Y":
		h.newHost = hostLine
		return nil
	default:
		return errors.New("user rejected host")
	}
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

	return u.store.Do(func() error {
		// New entry
		uuid, err := u.store.NewSync(kind)
		if err != nil {
			return err
		}

		user, err := u.getString("user")
		if err != nil {
			return err
		}

		host, err := u.getString("host")
		if err != nil {
			return err
		}

		port := "22"
		for {
			port, err = u.prompt(inputPromptColor.Sprint("port (22): "))
			if err != nil {
				return err
			}

			if len(port) == 0 {
				port = "22"
				break
			}

			_, err = strconv.Atoi(port)
			if err != nil {
				errColor.Printf("port must be an integer between %d and %d\n", 1, int(math.MaxUint16)-1)
				continue
			}

			break
		}

		file, err := u.getString("path")
		if err != nil {
			return err
		}

		// Use raw-er sets to avoid timestamp spam
		if err = u.store.Store.Set(uuid, txblob.KeySyncKind, kind); err != nil {
			return err
		}
		if err = u.store.Store.Set(uuid, txblob.KeyUser, user); err != nil {
			return err
		}
		if err = u.store.Store.Set(uuid, txblob.KeyHost, host); err != nil {
			return err
		}
		if err = u.store.Store.Set(uuid, txblob.KeyPort, port); err != nil {
			return err
		}
		if err = u.store.Store.Set(uuid, txblob.KeyPath, file); err != nil {
			return err
		}

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

			if err = u.store.Set(uuid, txblob.KeySecret, string(bytes.TrimSpace(b))); err != nil {
				return err
			}
			if err = u.store.Set(uuid, txblob.KeyPub, publicStr); err != nil {
				return err
			}

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

			if err = u.store.Set(uuid, txblob.KeySecret, string(bytes.TrimSpace(b))); err != nil {
				return err
			}
			if err = u.store.Set(uuid, txblob.KeyPub, publicStr); err != nil {
				return err
			}

			infoColor.Printf("successfully generated new rsa-4096 key:\n%s\n", publicStr)

		case 2:
			pass, err := u.getPassword()
			if err != nil {
				return err
			}

			if err = u.store.Set(uuid, txblob.KeyUser, user); err != nil {
				return err
			}
			if err = u.store.Set(uuid, txblob.KeyPass, pass); err != nil {
				return err
			}
		default:
			panic("how did this happen?")
		}

		if err = u.store.AddSync(uuid); err != nil {
			return err
		}

		blob, err := u.store.Get(uuid)
		if err != nil {
			return err
		}

		fmt.Println()
		infoColor.Println("Added new sync entry:", blob.Name())

		return nil
	})
}

func (u *uiContext) syncRemove(name string) error {
	uuid, _, err := u.store.Find(name)
	if err != nil {
		return err
	}
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
