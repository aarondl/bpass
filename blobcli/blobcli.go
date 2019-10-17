package blobcli

import "io"

// UI is the user interface element that connects directly to the user
type UI interface {
	// Get a line from the user
	Get() (string, error)
	// GetSecure gets a line from a user securely with a prompt
	GetSecure(string) (string, error)

	io.Writer
}
