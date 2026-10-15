package model

import (
	"strings"
	"unicode/utf8"
)

// Trunc shortens s to at most n bytes without splitting a UTF-8 sequence and
// strips surrounding whitespace and NUL bytes.
func Trunc(s string, n int) string {
	s = strings.TrimSpace(strings.ReplaceAll(s, "\x00", ""))
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "?")
	}
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

func capList[T any](in []T, n int) []T {
	if in == nil {
		return []T{}
	}
	if len(in) > n {
		return in[:n]
	}
	return in
}

// Normalize enforces the server's schema limits (string lengths, list sizes,
// no nulls where lists/maps are expected), so a check-in is never rejected
// because one collector returned something unusually long.
func (r *Report) Normalize() {
	if r.SchemaVersion == 0 {
		r.SchemaVersion = 1
	}
	d := &r.Device
	if d.Hostname = Trunc(d.Hostname, 255); d.Hostname == "" {
		d.Hostname = "unknown"
	}
	d.OSName = Trunc(d.OSName, 128)
	d.OSVersion = Trunc(d.OSVersion, 64)
	d.OSBuild = Trunc(d.OSBuild, 64)
	d.Architecture = Trunc(d.Architecture, 32)
	d.SerialNumber = Trunc(d.SerialNumber, 128)
	d.Manufacturer = Trunc(d.Manufacturer, 128)
	d.Model = Trunc(d.Model, 128)
	d.CPU = Trunc(d.CPU, 255)
	d.Timezone = Trunc(d.Timezone, 64)
	d.AgentVersion = Trunc(d.AgentVersion, 32)
	d.Disks = capList(d.Disks, 64)
	for i := range d.Disks {
		d.Disks[i].Mount = Trunc(d.Disks[i].Mount, 255)
		d.Disks[i].Filesystem = Trunc(d.Disks[i].Filesystem, 64)
	}
	d.LoggedInUsers = capList(d.LoggedInUsers, 64)
	for i := range d.LoggedInUsers {
		d.LoggedInUsers[i] = Trunc(d.LoggedInUsers[i], 128)
	}
	d.Network = capList(d.Network, 64)
	for i := range d.Network {
		n := &d.Network[i]
		n.Name, n.MAC = Trunc(n.Name, 128), Trunc(n.MAC, 64)
		n.IPs = capList(n.IPs, 32)
		for j := range n.IPs {
			n.IPs[j] = Trunc(n.IPs[j], 64)
		}
	}
	if r.Posture == nil {
		r.Posture = map[string]PostureCheck{}
	}
	for k, c := range r.Posture {
		c.Detail = Trunc(c.Detail, 1000)
		if c.Error != nil {
			e := Trunc(*c.Error, 1000)
			c.Error = &e
		}
		if c.Data == nil {
			c.Data = map[string]any{}
		}
		r.Posture[k] = c
	}
	if r.Software != nil {
		r.Software = capList(r.Software, 10000)
		out := r.Software[:0]
		for _, s := range r.Software {
			s.Name = Trunc(s.Name, 255)
			if s.Name == "" {
				continue
			}
			s.Version = Trunc(s.Version, 128)
			s.Publisher = Trunc(s.Publisher, 255)
			s.Identifier = Trunc(s.Identifier, 255)
			s.InstallDate = Trunc(s.InstallDate, 32)
			s.Source = Trunc(s.Source, 32)
			out = append(out, s)
		}
		r.Software = out
	}
	if r.Errors == nil {
		r.Errors = map[string]string{}
	}
	for k, v := range r.Errors {
		r.Errors[k] = Trunc(v, 1000)
	}
}
