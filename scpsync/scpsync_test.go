package scpsync

import (
	"bytes"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestSend(t *testing.T) {
	// No t.Parallel(), sshd will bind to same port

	if testing.Short() {
		t.Skip("short skipping sshd test")
	}

	payload := "test"
	tmp, err := ioutil.TempFile("", "scpsendtest")
	if err != nil {
		t.Fatal(err)
	}
	tmp.Close()

	defer func() {
		if t.Failed() {
			t.Log("test failed, preserving temp file:", tmp.Name())
			return
		}

		b, err := ioutil.ReadFile(tmp.Name())
		if string(b) != payload {
			t.Errorf("file data did not match\nwant: %s\ngot: %s\n", payload, b)
		}

		if err = os.Remove(tmp.Name()); err != nil {
			t.Error("failed to remove temp file:", err)
		}
	}()

	out := new(bytes.Buffer)
	sshd := testSSHDServerCommand(t)
	if testing.Verbose() {
		sshd.Stderr = os.Stderr
		sshd.Stdout = os.Stdout
	}

	if err := sshd.Start(); err != nil {
		t.Fatal("failed to start ssh:", err)
	}

	// We have to wait for the sshd server to get up and running, could
	// poll on the port but I'm lazy
	time.Sleep(3 * time.Second)

	config := testSSHClientConfig(t)
	err = Send("127.0.0.1:22222", config, tmp.Name(), 0644, []byte(payload))
	if err != nil {
		t.Error(err)
	}

	if err := sshd.Process.Kill(); err != nil {
		t.Fatal("failed to kill ssh")
	}

	// We expect it to die and exit 1, we just want to know it's done
	_ = sshd.Wait()

	if t.Failed() {
		t.Logf("sshd out:\n%s\n", out.Bytes())
	}
}

func TestRecv(t *testing.T) {
	// No t.Parallel(), sshd will bind to same port

	if testing.Short() {
		t.Skip("short skipping sshd test")
	}

	out := new(bytes.Buffer)
	sshd := testSSHDServerCommand(t)
	if testing.Verbose() {
		sshd.Stderr = os.Stderr
		sshd.Stdout = os.Stdout
	}

	if err := sshd.Start(); err != nil {
		t.Fatal("failed to start ssh:", err)
	}

	// We have to wait for the sshd server to get up and running, could
	// poll on the port but I'm lazy
	time.Sleep(3 * time.Second)

	thisFile, err := filepath.Abs("scpsync_test.go")
	if err != nil {
		t.Fatal(err)
	}

	config := testSSHClientConfig(t)
	file, err := Recv("127.0.0.1:22222", config, thisFile)
	if err != nil {
		t.Error(err)
	}

	if !strings.HasPrefix(string(file), "package scpsync") {
		t.Error("probably have the wrong content!")
	}

	if err := sshd.Process.Kill(); err != nil {
		t.Fatal("failed to kill ssh")
	}

	// We expect it to die and exit 1, we just want to know it's done
	_ = sshd.Wait()

	if t.Failed() {
		t.Logf("sshd out:\n%s\n", out.Bytes())
	}
}

func testSSHClientConfig(t *testing.T) *ssh.ClientConfig {
	t.Helper()

	user := os.Getenv("USER")
	if len(user) == 0 {
		t.Skip("USER env variable not set, no idea who to log in as")
	}

	privKeyPem, err := ioutil.ReadFile("testdata/client.key")
	if err != nil {
		t.Fatal(err)
	}

	privKey, err := ssh.ParseRawPrivateKey(privKeyPem)
	if err != nil {
		t.Fatal(err)
	}

	signer, err := ssh.NewSignerFromKey(privKey)
	if err != nil {
		t.Fatal(err)
	}

	return &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: func(string, net.Addr, ssh.PublicKey) error {
			// We blindly accept! Take our security!
			return nil
		},
	}
}

func testSSHDServerCommand(t *testing.T) *exec.Cmd {
	t.Helper()

	sshdPath, err := exec.LookPath("sshd")
	if err != nil {
		t.Skip("could not find sshd in the path")
	}

	hostKeyPath, err := filepath.Abs("testdata/host.key")
	if err != nil {
		t.Fatal(err)
	}

	authKeysPath, err := filepath.Abs("testdata/sshd_authorized_keys")
	if err != nil {
		t.Fatal(err)
	}

	configPath, err := filepath.Abs("testdata/sshd_config")
	if err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(sshdPath, "-d", "-D", "-4", "-e",
		"-f", configPath,
		"-h", hostKeyPath,
		"-o", "AuthorizedKeysFile="+authKeysPath,
	)
	cmd.Dir = "testdata"

	return cmd
}

func TestSendFileProcess(t *testing.T) {
	t.Parallel()

	payload := "test"

	tmp, err := ioutil.TempFile("", "scpsendtest")
	if err != nil {
		t.Fatal(err)
	}
	tmp.Close()

	defer func() {
		if t.Failed() {
			t.Log("test failed, preserving temp file:", tmp.Name())
			return
		}

		b, err := ioutil.ReadFile(tmp.Name())
		if string(b) != payload {
			t.Errorf("file data did not match\nwant: %s\ngot: %s\n", payload, b)
		}

		if err = os.Remove(tmp.Name()); err != nil {
			t.Error("failed to remove temp file:", err)
		}
	}()

	// Send a file to scp process
	scpCmd := exec.Command("scp", "-qt", tmp.Name())

	// Open pipes to read and write to the process
	writePipe, err := scpCmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	readPipe, err := scpCmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}

	stream := readWriter{readPipe, writePipe}

	// Start scp
	if err = scpCmd.Start(); err != nil {
		t.Fatal(err)
	}

	waiter := make(chan struct{})
	go func() {
		err := sendFile(
			stream, strings.NewReader(payload),
			"whocares", int64(len(payload)), 0644)
		if err != nil {
			t.Error(err)
		}
		if err = writePipe.Close(); err != nil {
			t.Error(err)
		}

		close(waiter)
	}()

	if err = scpCmd.Wait(); err != nil {
		t.Error(err)
	}

	// Wait for our goroutine before leaving the test
	<-waiter
}

func TestRecvFileProcess(t *testing.T) {
	t.Parallel()

	// Send a file to scp process
	scpCmd := exec.Command("scp", "-qf", "scpsync_test.go")

	// Open pipes to read and write to the process
	writePipe, err := scpCmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	readPipe, err := scpCmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}

	stream := readWriter{readPipe, writePipe}

	// Start scp
	if err = scpCmd.Start(); err != nil {
		t.Fatal(err)
	}

	waiter := make(chan struct{})
	go func() {
		file, err := readFile(stream)
		if err != nil {
			t.Error(err)
		}
		if err = writePipe.Close(); err != nil {
			t.Error(err)
		}

		b, err := ioutil.ReadFile("scpsync_test.go")
		if err != nil {
			t.Fatal(err)
		}

		if file.Filename != "scpsync_test.go" {
			t.Error("filename was wrong:", file.Filename)
		}
		if file.Mode != 0o644 {
			t.Errorf("mode was wrong: %od", file.Mode)
		}
		if !bytes.Equal(b, file.Contents) {
			lenb := len(b)
			lenc := len(file.Contents)
			if lenb > 20 {
				b = b[:20]
			}
			if lenc > 20 {
				file.Contents = file.Contents[:20]
			}
			t.Errorf("contents were wrong, want: %d bytes got: %d, content:\n%s\ngot:\n%s",
				lenb, lenc, b, file.Contents)
		}

		close(waiter)
	}()

	if err = scpCmd.Wait(); err != nil {
		t.Error(err)
	}

	// Wait for our goroutine before leaving the test
	<-waiter
}
