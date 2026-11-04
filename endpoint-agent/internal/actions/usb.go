package actions

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// Registry is HKEY_LOCAL_MACHINE (64-bit view).
type Registry interface {
	// GetDWORD returns a REG_DWORD value; exists is false when the key or value is absent.
	GetDWORD(key, name string) (value uint32, exists bool, err error)
	// SetDWORD writes a REG_DWORD value, creating the key when needed.
	SetDWORD(key, name string, value uint32) error
	// DeleteValue removes a value (no error when it is already absent).
	DeleteValue(key, name string) error
	KeyExists(key string) (bool, error)
	// DeleteKeyIfEmpty removes a key that has no values and no subkeys.
	DeleteKeyIfEmpty(key string) error
}

// USB mass-storage block (docs/DEVICE_MANAGEMENT.md#usb-storage-block). Two
// standard, documented Windows mechanisms, both fully reversible:
//
//   - USBSTOR Start=4: the USB mass-storage class driver no longer loads, so
//     newly connected USB drives get no volume. It does not cover UASP drives
//     (UASPStor) or card readers with their own drivers, and a drive that is
//     already connected keeps working until it is unplugged.
//   - "Removable Disks: Deny read / write / execute access" (the Group Policy
//     Removable Storage Access settings, class GUID
//     {53f5630d-b6bf-11d0-94f2-00a0c91efb8b}): Windows refuses access to any
//     removable disk, whatever its driver, including drives already connected
//     (new handles are denied). It does not affect phones (WPD), CD/DVD or
//     USB keyboards, mice, cameras and other non-storage devices.
//
// Together they block USB mass storage reliably; each value's previous state
// (including "absent") is saved first and put back exactly on unblock.
const (
	USBStorKey          = `SYSTEM\CurrentControlSet\Services\USBSTOR`
	RemovableStorageKey = `SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices`
	RemovableDisksClass = "{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}"
	RemovableDisksKey   = RemovableStorageKey + `\` + RemovableDisksClass
	usbStorDisabled     = 4
	denyValue           = 1
	usbStorStart        = "Start"
	denyAll             = "Deny_All"
	denyRead, denyWrite = "Deny_Read", "Deny_Write"
	denyExecute         = "Deny_Execute"
)

// blockValues are the values the block sets.
var blockValues = []savedValue{
	{Key: USBStorKey, Name: usbStorStart, Value: usbStorDisabled},
	{Key: RemovableDisksKey, Name: denyRead, Value: denyValue},
	{Key: RemovableDisksKey, Name: denyWrite, Value: denyValue},
	{Key: RemovableDisksKey, Name: denyExecute, Value: denyValue},
}

func (m *Manager) blockUSB(commandID string) Result {
	st, err := m.load()
	if err != nil {
		return failed("reading saved values: %v", err)
	}
	usbStor, err := m.Registry.KeyExists(USBStorKey)
	if err != nil {
		return failed("reading %s: %v", USBStorKey, err)
	}
	already := st.USB != nil
	if !already {
		// Save every value (and which keys exist) before changing anything.
		saved := &savedUSB{SavedAt: time.Now().UTC(), CommandID: commandID}
		for _, k := range []string{RemovableStorageKey, RemovableDisksKey} {
			ok, err := m.Registry.KeyExists(k)
			if err != nil {
				return failed("reading %s: %v", k, err)
			}
			if !ok {
				saved.CreatedKeys = append(saved.CreatedKeys, k)
			}
		}
		for _, v := range blockValues {
			if v.Key == USBStorKey && !usbStor {
				continue
			}
			cur, exists, err := m.Registry.GetDWORD(v.Key, v.Name)
			if err != nil {
				return failed("reading %s\\%s: %v", v.Key, v.Name, err)
			}
			saved.Values = append(saved.Values, savedValue{Key: v.Key, Name: v.Name, Exists: exists, Value: cur})
		}
		st.USB = saved
		if err := m.store(st); err != nil {
			return failed("could not save the current values, nothing was changed: %v", err)
		}
	}
	for _, v := range blockValues {
		if v.Key == USBStorKey && !usbStor {
			continue // never create the driver's service key
		}
		if err := m.Registry.SetDWORD(v.Key, v.Name, v.Value); err != nil {
			out := fmt.Sprintf("setting %s\\%s: %v", v.Key, v.Name, err)
			if !already {
				if rerr := m.restoreUSB(st.USB); rerr != nil {
					return failed("%s; rolling back also failed (%v) - the saved values are kept for unblock", out, rerr)
				}
				st.USB = nil
				_ = m.store(st)
				out += "; the previous values were restored"
			}
			return failed("%s", out)
		}
	}
	data := m.usbData()
	out := "USB mass storage blocked: USBSTOR driver disabled and removable disks denied (read, write, execute). " +
		"Drives connected now are refused; keyboards, mice and other non-storage USB devices keep working."
	if !usbStor {
		out = "USB mass storage blocked: removable disks denied (read, write, execute); this device has no USBSTOR driver key."
	}
	if already {
		out = "USB mass storage was already blocked by this agent; the block was re-applied (the saved original values are unchanged)."
	}
	return Result{Status: "succeeded", Output: out, Data: data}
}

func (m *Manager) unblockUSB() Result {
	st, err := m.load()
	if err != nil {
		return failed("reading saved values: %v", err)
	}
	if st.USB == nil {
		data := m.usbData()
		if data["blocked"] == true {
			return Result{Status: "failed", Data: data, Output: "USB storage is blocked, but not by this agent (for example by Group Policy " +
				"or another tool): there are no saved values to restore, so nothing was changed"}
		}
		return Result{Status: "succeeded", Output: "USB storage is not blocked: nothing to restore", Data: data}
	}
	if err := m.restoreUSB(st.USB); err != nil {
		return failed("restoring the previous values: %v (the saved values are kept; try again)", err)
	}
	st.USB = nil
	if err := m.store(st); err != nil {
		return failed("previous values restored, but the saved copy could not be cleared: %v", err)
	}
	data := m.usbData()
	out := "USB mass storage unblocked: the previous USBSTOR and removable-disk policy values were restored exactly."
	if data["blocked"] == true {
		out += " USB storage is still blocked by a setting this agent did not make (for example Group Policy)."
	}
	return Result{Status: "succeeded", Output: out, Data: data}
}

// restoreUSB writes back (or deletes) every saved value, then removes the
// keys the block created if they are empty again.
func (m *Manager) restoreUSB(s *savedUSB) error {
	var errs []error
	for _, v := range s.Values {
		var err error
		if v.Exists {
			err = m.Registry.SetDWORD(v.Key, v.Name, v.Value)
		} else {
			err = m.Registry.DeleteValue(v.Key, v.Name)
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("%s\\%s: %w", v.Key, v.Name, err))
		}
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	// Deepest first.
	for i := len(s.CreatedKeys) - 1; i >= 0; i-- {
		if err := m.Registry.DeleteKeyIfEmpty(s.CreatedKeys[i]); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// usbData is the current USB storage state (posture check usb_storage).
func (m *Manager) usbData() map[string]any {
	d := map[string]any{}
	start, ok, err := m.Registry.GetDWORD(USBStorKey, usbStorStart)
	if err == nil && ok {
		d["usbstor_start"] = start
	}
	get := func(key, name string) bool {
		v, ok, err := m.Registry.GetDWORD(key, name)
		return err == nil && ok && v == 1
	}
	d["removable_disks_deny_read"] = get(RemovableDisksKey, denyRead)
	d["removable_disks_deny_write"] = get(RemovableDisksKey, denyWrite)
	d["deny_all_removable"] = get(RemovableStorageKey, denyAll)
	d["blocked"] = (ok && err == nil && start == usbStorDisabled) || d["removable_disks_deny_read"] == true ||
		d["deny_all_removable"] == true
	return d
}

// USBStatus is the usb_storage posture data and detail for check-ins
// (ok=false when unsupported on this OS).
func (m *Manager) USBStatus() (data map[string]any, detail string, ok bool) {
	if !supportedOS || m.Registry == nil {
		return nil, "", false
	}
	// No m.mu here: a long uninstall must never delay a check-in (reads only).
	data = m.usbData()
	st, err := m.load()
	byAgent := err == nil && st.USB != nil
	data["blocked_by_agent"] = byAgent
	if byAgent {
		data["blocked_since"] = st.USB.SavedAt.Format(time.RFC3339)
	}
	switch {
	case data["blocked"] == true && byAgent:
		detail = "USB storage blocked by the CNAPP agent"
	case data["blocked"] == true:
		var why []string
		if v, ok := data["usbstor_start"].(uint32); ok && v == usbStorDisabled {
			why = append(why, "USBSTOR disabled")
		}
		if data["removable_disks_deny_read"] == true || data["deny_all_removable"] == true {
			why = append(why, "removable storage denied by policy")
		}
		detail = "USB storage blocked (" + strings.Join(why, ", ") + ")"
	default:
		detail = "USB storage allowed"
	}
	return data, detail, true
}
