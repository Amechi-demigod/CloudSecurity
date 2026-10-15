//go:build !darwin && !windows

package commands

import (
	"context"
	"errors"
)

// Lock is not implemented on this platform yet.
func Lock(context.Context) (string, error) {
	return "", errors.New("lock_device is not supported on this platform")
}
