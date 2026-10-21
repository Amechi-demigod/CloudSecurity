//go:build windows

package lostmode

import (
	"context"
	"errors"

	"golang.org/x/sys/windows/registry"
)

const policyKey = `SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`

type winBackend struct{}

func platformBackend() Backend { return winBackend{} }

func (winBackend) Name() string { return "sign-in legal notice (LegalNoticeCaption/LegalNoticeText)" }

func (winBackend) Get(context.Context) (Notice, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, policyKey, registry.QUERY_VALUE)
	if errors.Is(err, registry.ErrNotExist) {
		return Notice{}, nil
	}
	if err != nil {
		return Notice{}, err
	}
	defer k.Close()
	var n Notice
	if v, _, err := k.GetStringValue("LegalNoticeCaption"); err == nil {
		n.Caption, n.CaptionSet = v, true
	} else if !errors.Is(err, registry.ErrNotExist) {
		return Notice{}, err
	}
	if v, _, err := k.GetStringValue("LegalNoticeText"); err == nil {
		n.Text, n.TextSet = v, true
	} else if !errors.Is(err, registry.ErrNotExist) {
		return Notice{}, err
	}
	return n, nil
}

func (winBackend) Set(_ context.Context, n Notice) error {
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, policyKey, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	if err := k.SetStringValue("LegalNoticeCaption", n.Caption); err != nil {
		return err
	}
	return k.SetStringValue("LegalNoticeText", n.Text)
}

func (winBackend) Restore(_ context.Context, n Notice) error {
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, policyKey, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	for _, v := range []struct {
		name, val string
		set       bool
	}{{"LegalNoticeCaption", n.Caption, n.CaptionSet}, {"LegalNoticeText", n.Text, n.TextSet}} {
		if v.set {
			if err := k.SetStringValue(v.name, v.val); err != nil {
				return err
			}
		} else if err := k.DeleteValue(v.name); err != nil && !errors.Is(err, registry.ErrNotExist) {
			return err
		}
	}
	return nil
}
