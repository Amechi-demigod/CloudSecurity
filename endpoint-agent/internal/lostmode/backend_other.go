//go:build !windows && !darwin

package lostmode

import (
	"context"
	"errors"
)

type noBackend struct{}

func platformBackend() Backend { return noBackend{} }

func (noBackend) Name() string { return "lost-mode message (unsupported on this platform)" }

func (noBackend) Get(context.Context) (Notice, error) { return Notice{}, nil }

func (noBackend) Set(context.Context, Notice) error {
	return errors.New("lost mode is not supported on this platform")
}

func (noBackend) Restore(context.Context, Notice) error { return nil }
