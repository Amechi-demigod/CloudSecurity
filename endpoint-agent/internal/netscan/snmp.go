package netscan

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/gosnmp/gosnmp"
)

// SNMP limits.
const (
	maxInterfaces = 512
	maxFDB        = 4096
	maxBasePorts  = 4096
	snmpBudget    = 20 * time.Second // total SNMP time per device
	bulkReps      = 10               // small max-repetitions
)

// OIDs (read-only GET / GETBULK only; never a SET).
const (
	oidSysDescr    = "1.3.6.1.2.1.1.1.0"
	oidSysObjectID = "1.3.6.1.2.1.1.2.0"
	oidSysUpTime   = "1.3.6.1.2.1.1.3.0"
	oidSysContact  = "1.3.6.1.2.1.1.4.0"
	oidSysName     = "1.3.6.1.2.1.1.5.0"
	oidSysLocation = "1.3.6.1.2.1.1.6.0"

	oidEntClass    = "1.3.6.1.2.1.47.1.1.1.1.5"
	oidEntSoftRev  = "1.3.6.1.2.1.47.1.1.1.1.10"
	oidEntSerial   = "1.3.6.1.2.1.47.1.1.1.1.11"
	oidEntModel    = "1.3.6.1.2.1.47.1.1.1.1.13"
	entClassChasis = 3

	oidIfDescr      = "1.3.6.1.2.1.2.2.1.2"
	oidIfPhysAddr   = "1.3.6.1.2.1.2.2.1.6"
	oidIfOperStatus = "1.3.6.1.2.1.2.2.1.8"
	oidIfName       = "1.3.6.1.2.1.31.1.1.1.1"
	oidIfHighSpeed  = "1.3.6.1.2.1.31.1.1.1.15"

	oidBasePortIfIndex = "1.3.6.1.2.1.17.1.4.1.2"
	oidDot1dFdbPort    = "1.3.6.1.2.1.17.4.3.1.2"
	oidDot1qFdbPort    = "1.3.6.1.2.1.17.7.1.2.2.1.2"
)

var sysOIDs = []string{oidSysDescr, oidSysObjectID, oidSysUpTime, oidSysContact, oidSysName, oidSysLocation}

// SNMPInfo is the "snmp" block of a device (contract).
type SNMPInfo struct {
	Version      string `json:"version"`
	CredentialID any    `json:"credential_id"`
	SysName      string `json:"sys_name"`
	SysDescr     string `json:"sys_descr"`
	SysObjectID  string `json:"sys_object_id"`
	SysLocation  string `json:"sys_location"`
	SysContact   string `json:"sys_contact"`
	UptimeS      int64  `json:"uptime_s"`
}

// Interface is one IF-MIB row.
type Interface struct {
	Index     int    `json:"index"`
	Name      string `json:"name"`
	Descr     string `json:"descr"`
	MAC       string `json:"mac"`
	OperUp    bool   `json:"oper_up"`
	SpeedMbps int64  `json:"speed_mbps"`
}

// FDBEntry is one bridge forwarding-table row.
type FDBEntry struct {
	MAC      string `json:"mac"`
	PortName string `json:"port_name"`
	VLAN     int    `json:"vlan"`
}

// snmpResult is everything learned from SNMP about one device.
type snmpResult struct {
	Info             *SNMPInfo
	DefaultCommunity *string
	Vendor, Model    string
	Firmware, Serial string
	DeviceType       string
	Interfaces       []Interface
	FDB              []FDBEntry
}

var errStopWalk = errors.New("stop walk")

func (e *Env) snmpTimeout() time.Duration {
	if e.SNMPTimeout > 0 {
		return e.SNMPTimeout
	}
	return 1500 * time.Millisecond
}

func (e *Env) snmpPort() uint16 {
	if e.SNMPPort != 0 {
		return e.SNMPPort
	}
	return 161
}

func (e *Env) snmpBudget() time.Duration {
	if e.SNMPBudget > 0 {
		return e.SNMPBudget
	}
	return snmpBudget
}

// buildSNMP configures a session for one credential (nothing is sent yet).
func (e *Env) buildSNMP(ctx context.Context, ip string, c Credential, retries int) *gosnmp.GoSNMP {
	g := &gosnmp.GoSNMP{Target: ip, Port: e.snmpPort(), Transport: "udp", Timeout: e.snmpTimeout(), Retries: retries,
		MaxRepetitions: bulkReps, Context: ctx}
	if e.Limiter != nil {
		lim := e.Limiter
		g.PreSend = func(*gosnmp.GoSNMP) { _ = lim.Wait(ctx) }
	}
	switch c.Version {
	case "v3":
		g.Version = gosnmp.Version3
		g.SecurityModel = gosnmp.UserSecurityModel
		sp := &gosnmp.UsmSecurityParameters{UserName: c.Username, AuthenticationPassphrase: c.AuthPassword}
		switch c.AuthProto {
		case "SHA256":
			sp.AuthenticationProtocol = gosnmp.SHA256
		case "SHA512":
			sp.AuthenticationProtocol = gosnmp.SHA512
		default:
			sp.AuthenticationProtocol = gosnmp.SHA
		}
		if c.Level == "authPriv" {
			g.MsgFlags = gosnmp.AuthPriv
			sp.PrivacyPassphrase = c.PrivPassword
			if c.PrivProto == "AES256" {
				sp.PrivacyProtocol = gosnmp.AES256
			} else {
				sp.PrivacyProtocol = gosnmp.AES
			}
		} else {
			g.MsgFlags = gosnmp.AuthNoPriv
			sp.PrivacyProtocol = gosnmp.NoPriv
		}
		g.SecurityParameters = sp
	default:
		g.Version = gosnmp.Version2c
		g.Community = c.Community
	}
	return g
}

// noAgent reports a quick "nothing listens on UDP 161" answer (ICMP port
// unreachable surfaces as a refused / reset connected socket).
func noAgent(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return true
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "connection refused") || strings.Contains(s, "forcibly closed")
}

func pduBytes(p gosnmp.SnmpPDU) []byte {
	switch v := p.Value.(type) {
	case []byte:
		return v
	case string:
		return []byte(v)
	}
	return nil
}

func pduInt(p gosnmp.SnmpPDU) (int64, bool) {
	switch v := p.Value.(type) {
	case int:
		return int64(v), true
	case int32:
		return int64(v), true
	case int64:
		return v, true
	case uint:
		return int64(v), true
	case uint32:
		return int64(v), true
	case uint64:
		return int64(v), true
	}
	return 0, false
}

func pduString(p gosnmp.SnmpPDU, n int) string {
	if p.Type == gosnmp.NoSuchObject || p.Type == gosnmp.NoSuchInstance || p.Type == gosnmp.EndOfMibView {
		return ""
	}
	switch v := p.Value.(type) {
	case []byte, string:
		return cleanBanner(pduBytes(p), n)
	case nil:
		return ""
	default:
		_ = v
		if i, ok := pduInt(p); ok {
			return strconv.FormatInt(i, 10)
		}
	}
	return ""
}

func macString(b []byte) string {
	if len(b) != 6 {
		return ""
	}
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", b[0], b[1], b[2], b[3], b[4], b[5])
}

// walk bulk-walks root and calls fn(suffix, pdu) for at most limit entries.
func walk(g *gosnmp.GoSNMP, root string, limit int, fn func(suffix string, p gosnmp.SnmpPDU)) {
	n := 0
	prefix := "." + root + "."
	_ = g.BulkWalk(root, func(p gosnmp.SnmpPDU) error {
		if n >= limit {
			return errStopWalk
		}
		n++
		fn(strings.TrimPrefix(p.Name, prefix), p)
		return nil
	})
}

// probeSupplied tries the credentials in order and stops at the first that
// answers a sysDescr GET. It returns the live session (caller closes) or nil.
// refused is true when the device has no SNMP agent on the port at all.
func (e *Env) probeSupplied(ctx context.Context, ip string, creds []Credential, retries int) (g *gosnmp.GoSNMP, info *SNMPInfo, refused bool) {
	for _, c := range creds {
		if ctx.Err() != nil {
			return nil, nil, false
		}
		s := e.buildSNMP(ctx, ip, c, retries)
		if err := s.Connect(); err != nil {
			continue
		}
		pkt, err := s.Get(sysOIDs)
		if err == nil && pkt != nil && pkt.Error == gosnmp.NoError && len(pkt.Variables) >= 1 &&
			pkt.Variables[0].Type == gosnmp.OctetString {
			return s, sysInfo(pkt, c), false
		}
		_ = s.Close()
		if noAgent(err) {
			return nil, nil, true
		}
	}
	return nil, nil, false
}

func sysInfo(pkt *gosnmp.SnmpPacket, c Credential) *SNMPInfo {
	in := &SNMPInfo{Version: c.Version, CredentialID: c.ID}
	for _, v := range pkt.Variables {
		switch strings.TrimPrefix(v.Name, ".") {
		case oidSysDescr:
			in.SysDescr = pduString(v, 512)
		case oidSysObjectID:
			in.SysObjectID = strings.TrimPrefix(pduString(v, 128), ".")
			if s, ok := v.Value.(string); ok {
				in.SysObjectID = strings.TrimPrefix(s, ".")
			}
		case oidSysUpTime:
			if t, ok := pduInt(v); ok {
				in.UptimeS = t / 100
			}
		case oidSysContact:
			in.SysContact = pduString(v, 256)
		case oidSysName:
			in.SysName = pduString(v, 256)
		case oidSysLocation:
			in.SysLocation = pduString(v, 256)
		}
	}
	return in
}

// defaultCommunity sends ONE sysDescr GET with community "public" and ONE
// with "private" (v2c, no retry) - nothing else, no dictionary. Communities
// the operator supplied and that already answered are not re-sent.
func (e *Env) defaultCommunity(ctx context.Context, ip string, known string) *string {
	var found *string
	for _, comm := range []string{"public", "private"} {
		hit := known == comm
		if !hit {
			if ctx.Err() != nil {
				break
			}
			g := e.buildSNMP(ctx, ip, Credential{Version: "v2c", Community: comm}, 0)
			if g.Connect() == nil {
				pkt, err := g.Get([]string{oidSysDescr})
				hit = err == nil && pkt != nil && pkt.Error == gosnmp.NoError && len(pkt.Variables) > 0 &&
					pkt.Variables[0].Type == gosnmp.OctetString
				_ = g.Close()
			}
		}
		if hit {
			c := comm
			found = &c // "private" wins when both answer (the more serious finding)
		}
	}
	return found
}

// snmpProbe runs the whole SNMP phase for one device. alive: the host
// answered ping / ARP / a TCP port (default-community probing and extra
// retries only happen for those; a host that did not answer anything is only
// tried with the supplied credentials, once each).
func (e *Env) snmpProbe(ctx context.Context, ip string, creds []Credential, alive bool) *snmpResult {
	if e.SNMPHost != nil {
		h, ok := e.SNMPHost(ip)
		if !ok {
			return nil
		}
		ip = h
	}
	ctx, cancel := context.WithTimeout(ctx, e.snmpBudget())
	defer cancel()
	retries := 1
	if !alive {
		retries = 0
	}
	res := &snmpResult{}
	g, info, refused := e.probeSupplied(ctx, ip, creds, retries)
	if g != nil {
		defer g.Close()
		res.Info = info
		e.snmpDeep(g, res)
		fillHints(res)
	}
	if g == nil && (refused || !alive) {
		return nil
	}
	if g == nil || res.Info.Version == "v2c" {
		known := ""
		if g != nil {
			known = g.Community
		}
		res.DefaultCommunity = e.defaultCommunity(ctx, ip, known)
	}
	if g == nil && res.DefaultCommunity == nil {
		return nil
	}
	return res
}

// snmpDeep reads ENTITY-MIB, IF-MIB and the bridge tables over an
// established session. Every part is best effort.
func (e *Env) snmpDeep(g *gosnmp.GoSNMP, res *snmpResult) {
	// ENTITY-MIB: the first chassis entry (else the first entry).
	first, chassis := "", ""
	walk(g, oidEntClass, 256, func(suffix string, p gosnmp.SnmpPDU) {
		if first == "" {
			first = suffix
		}
		if v, _ := pduInt(p); v == entClassChasis && chassis == "" {
			chassis = suffix
		}
	})
	idx := chassis
	if idx == "" {
		idx = first
	}
	if idx != "" && validIndex(idx) {
		if pkt, err := g.Get([]string{oidEntSerial + "." + idx, oidEntModel + "." + idx, oidEntSoftRev + "." + idx}); err == nil &&
			pkt != nil && pkt.Error == gosnmp.NoError {
			for _, v := range pkt.Variables {
				s := pduString(v, 128)
				switch {
				case strings.HasPrefix(v.Name, "."+oidEntSerial+"."):
					res.Serial = s
				case strings.HasPrefix(v.Name, "."+oidEntModel+"."):
					res.Model = s
				case strings.HasPrefix(v.Name, "."+oidEntSoftRev+"."):
					res.Firmware = s
				}
			}
		}
	}

	// IF-MIB: ifDescr defines the (capped) interface set; the other columns
	// only fill those rows.
	ifs := map[int]*Interface{}
	var order []int
	walk(g, oidIfDescr, maxInterfaces, func(suffix string, p gosnmp.SnmpPDU) {
		i, err := strconv.Atoi(suffix)
		if err != nil || ifs[i] != nil {
			return
		}
		ifs[i] = &Interface{Index: i, Descr: pduString(p, 128)}
		order = append(order, i)
	})
	fill := func(root string, set func(it *Interface, p gosnmp.SnmpPDU)) {
		if len(ifs) == 0 {
			return
		}
		walk(g, root, maxInterfaces+64, func(suffix string, p gosnmp.SnmpPDU) {
			if i, err := strconv.Atoi(suffix); err == nil && ifs[i] != nil {
				set(ifs[i], p)
			}
		})
	}
	fill(oidIfName, func(it *Interface, p gosnmp.SnmpPDU) { it.Name = pduString(p, 64) })
	fill(oidIfPhysAddr, func(it *Interface, p gosnmp.SnmpPDU) { it.MAC = macString(pduBytes(p)) })
	fill(oidIfOperStatus, func(it *Interface, p gosnmp.SnmpPDU) { v, _ := pduInt(p); it.OperUp = v == 1 })
	fill(oidIfHighSpeed, func(it *Interface, p gosnmp.SnmpPDU) { it.SpeedMbps, _ = pduInt(p) })
	for _, i := range order {
		it := ifs[i]
		if it.Name == "" {
			it.Name = it.Descr
		}
		res.Interfaces = append(res.Interfaces, *it)
	}

	// BRIDGE-MIB / Q-BRIDGE-MIB forwarding table.
	portIf := map[int]int{}
	var fdb []FDBEntry
	portName := func(port int) string {
		if i, ok := portIf[port]; ok && ifs[i] != nil {
			return ifs[i].Name
		}
		return "port" + strconv.Itoa(port)
	}
	collect := func(root string, withVLAN bool) {
		walk(g, root, maxFDB, func(suffix string, p gosnmp.SnmpPDU) {
			parts := strings.Split(suffix, ".")
			vlan := 0
			if withVLAN {
				if len(parts) != 7 {
					return
				}
				vlan, _ = strconv.Atoi(parts[0])
				parts = parts[1:]
			}
			if len(parts) != 6 {
				return
			}
			var mac [6]byte
			for i, s := range parts {
				n, err := strconv.Atoi(s)
				if err != nil || n < 0 || n > 255 {
					return
				}
				mac[i] = byte(n)
			}
			port, ok := pduInt(p)
			if !ok || port <= 0 { // 0: the entry is for the bridge itself
				return
			}
			fdb = append(fdb, FDBEntry{MAC: macString(mac[:]), PortName: strconv.Itoa(int(port)), VLAN: vlan})
		})
	}
	collect(oidDot1qFdbPort, true)
	if len(fdb) == 0 {
		collect(oidDot1dFdbPort, false)
	}
	if len(fdb) > 0 {
		walk(g, oidBasePortIfIndex, maxBasePorts, func(suffix string, p gosnmp.SnmpPDU) {
			port, err1 := strconv.Atoi(suffix)
			ifi, ok := pduInt(p)
			if err1 == nil && ok {
				portIf[port] = int(ifi)
			}
		})
		for i := range fdb {
			n, _ := strconv.Atoi(fdb[i].PortName)
			fdb[i].PortName = portName(n)
		}
		res.FDB = fdb
	}
}

func validIndex(s string) bool {
	for _, r := range s {
		if (r < '0' || r > '9') && r != '.' {
			return false
		}
	}
	return s != ""
}

// enterprises maps IANA enterprise numbers (sysObjectID 1.3.6.1.4.1.N) to a
// vendor name. Best-effort hints; the server normalises authoritatively.
var enterprises = map[int]string{9: "Cisco", 11: "HP", 25: "Hewlett Packard Enterprise", 43: "3Com", 171: "D-Link",
	207: "Allied Telesis", 253: "Xerox", 311: "Microsoft", 318: "APC", 534: "Eaton", 674: "Dell", 890: "Zyxel",
	1916: "Extreme Networks", 1991: "Brocade", 2011: "Huawei", 2620: "Check Point", 2636: "Juniper", 3224: "NetScreen",
	3375: "F5", 3955: "Linksys", 4526: "Netgear", 5951: "Citrix", 6027: "Dell", 6486: "Alcatel-Lucent",
	6876: "VMware", 8072: "Net-SNMP", 10002: "Ubiquiti", 11863: "TP-Link", 12356: "Fortinet", 14179: "Aruba",
	14988: "MikroTik", 25461: "Palo Alto Networks", 25506: "H3C", 30065: "Arista", 41112: "Ubiquiti"}

func enterpriseOf(oid string) int {
	const pre = "1.3.6.1.4.1."
	if !strings.HasPrefix(oid, pre) {
		return 0
	}
	rest := oid[len(pre):]
	if i := strings.IndexByte(rest, '.'); i >= 0 {
		rest = rest[:i]
	}
	n, _ := strconv.Atoi(rest)
	return n
}

// fillHints derives vendor / device_type guesses (empty when not obvious).
func fillHints(r *snmpResult) {
	if r.Info == nil {
		return
	}
	r.Vendor = enterprises[enterpriseOf(r.Info.SysObjectID)]
	d := strings.ToLower(r.Info.SysDescr)
	has := func(words ...string) bool {
		for _, w := range words {
			if strings.Contains(d, w) {
				return true
			}
		}
		return false
	}
	switch {
	case has("printer", "laserjet", "officejet", "jetdirect", "imagerunner", "bizhub"):
		r.DeviceType = "printer"
	case has("firewall", "fortigate", "pan-os", "asa ", "checkpoint", "sonicwall"):
		r.DeviceType = "firewall"
	case has("access point", "wireless ap", "wlan controller"):
		r.DeviceType = "access_point"
	case has("uninterruptible", "smart-ups", "apc "):
		r.DeviceType = "ups"
	case has("router", "routeros", "edgerouter"):
		r.DeviceType = "router"
	case has("switch") || len(r.FDB) > 0:
		r.DeviceType = "switch"
	case has("linux", "windows", "freebsd", "esxi", "vmware", "darwin"):
		r.DeviceType = "server"
	}
}
