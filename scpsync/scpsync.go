// Package scpsync implements the bare minimum of the scp over ssh protocol
// in order to be able to download and upload a single file.
//
// Given this protocol is poorly documented outside of source code and this
// old deleted website [1] we'll document what we need to rely on here.
//
// [1] https://web.archive.org/web/20170215184048/https://blogs.oracle.com/janp/entry/how_the_scp_protocol_works
//
// For an upload an SSH connection is created and the scp process is started
// on the remote end by running `scp -t filename` (this undocumented flag puts
// it in sink mode). In this mode it's a MSG REPLY type of protocol where the
// process on the remote end will always give us a response.
//
//  Messages (these are strings followed by \n):
//    Cmmmm <length> <filename>\nDATA\n
//      single file copy, mmmm = mode (eg, 0644), length = bytes, DATA = contents
//
//  Replies:
//    0 (OK)
//    1 (warn)
//    2 (fatal - will end connection)
//  These replies are followed by a newline, there may be a message between
//  the reply in binary and the \n that can be displayed to the user.
//
// File size is restricted to int64 (not uint64)
//
// Of particular note is the way the "acks" work. In source mode (-f):
//
//  client: 0
//  scp -f: Cmmmm <length> <filename>\n
//  client: 0
//  scp -f: DATA (<length> bytes)
//  client: 0
//  scp -f: process exits 0
//
// And the way it works in sink mode (-t):
//
//  client: Cmmmm <length> <filename>\n
//  client: DATA (length bytes)
//  client: 0
//  scp -t: 0
//
// Note any of the above 0's could possibly be a 1 or a 2 with a message.
package scpsync

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"
)

type readWriter struct {
	io.Reader
	io.Writer
}

// Recv connects to host:port via tcp with a given client configuration
// and uses scp to download the file contents from the remote host.
func Recv(hostport string, config *ssh.ClientConfig, filename string) ([]byte, error) {
	client, err := ssh.Dial("tcp", hostport, config)
	if err != nil {
		return nil, err
	}

	session, err := client.NewSession()
	if err != nil {
		return nil, err
	}

	stderr := new(bytes.Buffer)
	session.Stderr = stderr

	write, err := session.StdinPipe()
	if err != nil {
		return nil, err
	}
	read, err := session.StdoutPipe()
	if err != nil {
		return nil, err
	}

	stream := readWriter{Reader: read, Writer: write}

	if err = session.Start("scp -qf " + filename); err != nil {
		return nil, err
	}

	var file scpFile
	waiter := make(chan struct{})
	go func() {
		file, err = readFile(stream)
		if err != nil {
			return
		}

		if err = write.Close(); err != nil {
			return
		}

		close(waiter)
	}()

	<-waiter

	// The goroutine can produce an error like this
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	if err = session.Wait(); err != nil {
		return nil, fmt.Errorf("failed to wait for scp: %w", err)
	}
	if err = client.Close(); err != nil {
		return nil, fmt.Errorf("failed to close ssh connection: %w", err)
	}

	return file.Contents, err
}

// Send connects to host:port via tcp with a given client configuration
// and uses scp to write the file contents to the remote host to 'filename' with
// the given mode. As per SCP semantics, the mode is ignored if the file exists.
func Send(hostport string, config *ssh.ClientConfig, filename string, mode int, contents []byte) error {
	client, err := ssh.Dial("tcp", hostport, config)
	if err != nil {
		return err
	}

	session, err := client.NewSession()
	if err != nil {
		return err
	}

	stderr := new(bytes.Buffer)
	session.Stderr = stderr

	write, err := session.StdinPipe()
	if err != nil {
		return err
	}
	read, err := session.StdoutPipe()
	if err != nil {
		return err
	}

	stream := readWriter{Reader: io.TeeReader(read, os.Stdout), Writer: write}

	if err = session.Start("scp -qt " + filename); err != nil {
		return err
	}

	waiter := make(chan struct{})
	go func() {
		err = sendFile(stream,
			bytes.NewReader(contents), filename, int64(len(contents)), mode)
		if err != nil {
			return
		}

		if err = write.Close(); err != nil {
			return
		}

		close(waiter)
	}()

	<-waiter

	if err = session.Wait(); err != nil {
		return fmt.Errorf("failed to wait for scp: %w", err)
	}
	if err = client.Close(); err != nil {
		return fmt.Errorf("failed to close ssh connection: %w", err)
	}

	return err
}

type scpFile struct {
	Filename string
	Length   int64
	Mode     int
	Contents []byte
}

// Err is a response error from the binary saying that something went wrong.
type Err struct {
	Code int
	Msg  string
}

// Error interface
func (e Err) Error() string {
	errStr := fmt.Sprintf("error code %d from scp", e.Code)
	if len(e.Msg) != 0 {
		errStr += ": " + e.Msg
	}
	return errStr
}

func sendFile(stream io.ReadWriter, file io.Reader, filename string, ln int64, mode int) error {
	// Send header
	_, err := fmt.Fprintf(stream, "C0%o %d %s\n", mode, ln, filepath.Base(filename))
	if err != nil {
		return fmt.Errorf("failed to send create message: %w", err)
	}

	// Copy the data
	n, err := io.Copy(stream, file)
	if err != nil {
		return fmt.Errorf("failed to deliver file data: %w", err)
	} else if n != ln {
		return fmt.Errorf("failed to deliver file data bytes, expected to copy %d but copied %d", ln, n)
	}

	// Have to send spurious \0's for it to continue processing
	if err := sendOKResponse(stream); err != nil {
		return err
	}

	return readResponse(stream)
}

func readFile(stream io.ReadWriter) (file scpFile, err error) {
	// First 0 byte acknowledges the beginning of the transfer (why????)
	if err = sendOKResponse(stream); err != nil {
		return file, err
	}

	reader := bufio.NewReader(stream)

	str, err := reader.ReadString('\n')
	if err != nil {
		return file, fmt.Errorf("failed to read intitial file header: %w", err)
	} else if len(str) == 0 {
		return file, errors.New("empty request")
	}

	// Acknowledge we've received the initial header
	if err = sendOKResponse(stream); err != nil {
		return file, err
	}

	if str[0] != 'C' {
		return file, fmt.Errorf("want initial character C but got: %c", str[0])
	}

	str = str[1:]

	fields := strings.Fields(str)
	if len(fields) != 3 {
		return file, fmt.Errorf("protocol demands 3 fields, got %d", len(fields))
	}

	mode, err := strconv.ParseInt(fields[0], 8, 32)
	if err != nil {
		return file, fmt.Errorf("failed to parse the mode: %q (%w)", fields[0], err)
	}

	length, err := strconv.ParseInt(fields[1], 10, 32)
	if err != nil {
		return file, fmt.Errorf("failed to parse the length: %q (%w)", fields[1], err)
	}

	file.Contents = make([]byte, length+1)
	if n, err := reader.Read(file.Contents); err != nil {
		return file, err
	} else if int64(n) != length+1 {
		return file, fmt.Errorf("short read, want %d bytes but got %d", length, n)
	}

	if file.Contents[len(file.Contents)-1] != 0 {
		return file, errors.New("protocol error, expect 0 byte after file data")
	}

	// Acknowledge we've received the file
	if err = sendOKResponse(stream); err != nil {
		return file, err
	}

	file.Filename = fields[2]
	file.Mode = int(mode)
	file.Length = length
	// Truncate the \0 byte
	file.Contents = file.Contents[:len(file.Contents)-1]

	return file, nil
}

func sendOKResponse(stream io.Writer) error {
	_, err := stream.Write([]byte{0})
	return err
}

func readResponse(stream io.Reader) error {
	// Get the response
	response := make([]byte, 256)
	nRead, err := stream.Read(response)
	if err != nil {
		return err
	} else if nRead == 0 {
		return errors.New("failed to read a response byte")
	}

	switch response[0] {
	case 0:
		return nil
	case 1, 2:
		var e Err
		if nRead > 2 {
			e.Msg = string(response[1:nRead])
		}
		e.Code = int(response[0])
		return e
	default:
		return fmt.Errorf("unknown response from scp: %x", response[:nRead])
	}
}
