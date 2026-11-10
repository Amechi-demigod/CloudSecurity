package netscan

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/gosnmp/gosnmp"
)

// fakeAgent is an in-process SNMPv2c agent on a loopback UDP port (gosnmp
// ships none). It answers GET / GETNEXT / GETBULK from a static MIB for the
// accepted communities, silently drops other communities (like real agents),
// never answers a SET, and logs every request.
type fakeAgent struct {
	t         *testing.T
	conn      net.PacketConn
	accept    map[string]bool
	mu        sync.Mutex
	log       []fakeReq
	oids      []string // sorted
	vals      map[string]gosnmp.SnmpPDU
	setSeen   bool
	setsGiven int
}

type fakeReq struct {
	Community string
	Type      gosnmp.PDUType
	OIDs      []string
}

func oidParts(s string) []int {
	var out []int
	for _, p := range strings.Split(strings.TrimPrefix(s, "."), ".") {
		n, _ := strconv.Atoi(p)
		out = append(out, n)
	}
	return out
}

func oidLess(a, b string) bool {
	x, y := oidParts(a), oidParts(b)
	for i := 0; i < len(x) && i < len(y); i++ {
		if x[i] != y[i] {
			return x[i] < y[i]
		}
	}
	return len(x) < len(y)
}

func newFakeAgent(t *testing.T, communities ...string) *fakeAgent {
	t.Helper()
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no loopback UDP: %v", err)
	}
	a := &fakeAgent{t: t, conn: conn, accept: map[string]bool{}, vals: map[string]gosnmp.SnmpPDU{}}
	for _, c := range communities {
		a.accept[c] = true
	}
	go a.serve()
	t.Cleanup(func() { _ = conn.Close() })
	return a
}

func (a *fakeAgent) port() uint16 { return uint16(a.conn.LocalAddr().(*net.UDPAddr).Port) }

func (a *fakeAgent) set(oid string, typ gosnmp.Asn1BER, v any) {
	oid = strings.TrimPrefix(oid, ".")
	if _, ok := a.vals["."+oid]; !ok {
		a.oids = append(a.oids, oid)
	}
	a.vals["."+oid] = gosnmp.SnmpPDU{Name: "." + oid, Type: typ, Value: v}
}

func (a *fakeAgent) str(oid, v string) { a.set(oid, gosnmp.OctetString, []byte(v)) }

func (a *fakeAgent) finish() {
	sort.Slice(a.oids, func(i, j int) bool { return oidLess(a.oids[i], a.oids[j]) })
}

// populateSystem fills the system group and a chassis entity.
func (a *fakeAgent) populateSystem(descr, objectID string) {
	a.str("1.3.6.1.2.1.1.1.0", descr)
	a.set("1.3.6.1.2.1.1.2.0", gosnmp.ObjectIdentifier, "."+objectID)
	a.set("1.3.6.1.2.1.1.3.0", gosnmp.TimeTicks, uint32(360000))
	a.str("1.3.6.1.2.1.1.4.0", "noc@example.test")
	a.str("1.3.6.1.2.1.1.5.0", "sw-core-1")
	a.str("1.3.6.1.2.1.1.6.0", "Rack 4")
	a.set("1.3.6.1.2.1.47.1.1.1.1.5.1", gosnmp.Integer, 10) // a container first
	a.set("1.3.6.1.2.1.47.1.1.1.1.5.1001", gosnmp.Integer, 3)
	a.str("1.3.6.1.2.1.47.1.1.1.1.10.1001", "15.2(7)E3")
	a.str("1.3.6.1.2.1.47.1.1.1.1.11.1001", "FOC1234X0AB")
	a.str("1.3.6.1.2.1.47.1.1.1.1.13.1001", "WS-C3750X-48P")
}

func (a *fakeAgent) populateInterfaces(n int) {
	for i := 1; i <= n; i++ {
		s := strconv.Itoa(i)
		a.str("1.3.6.1.2.1.2.2.1.2."+s, "GigabitEthernet1/0/"+s)
		a.set("1.3.6.1.2.1.2.2.1.6."+s, gosnmp.OctetString, []byte{0, 0x1b, 0x2c, 0x3d, 0x4e, byte(i)})
		a.set("1.3.6.1.2.1.2.2.1.8."+s, gosnmp.Integer, 1+i%2)
		a.str("1.3.6.1.2.1.31.1.1.1.1."+s, "Gi1/0/"+s)
		a.set("1.3.6.1.2.1.31.1.1.1.15."+s, gosnmp.Gauge32, uint(1000))
	}
}

// populateFDB adds n Q-BRIDGE forwarding entries on VLAN 10 and the port map.
func (a *fakeAgent) populateFDB(n int) {
	for i := 0; i < n; i++ {
		mac := fmt.Sprintf("0.17.34.%d.%d.%d", i/65536, (i/256)%256, i%256)
		a.set("1.3.6.1.2.1.17.7.1.2.2.1.2.10."+mac, gosnmp.Integer, 1+i%4)
	}
	for p := 1; p <= 4; p++ {
		a.set("1.3.6.1.2.1.17.1.4.1.2."+strconv.Itoa(p), gosnmp.Integer, p)
	}
}

func (a *fakeAgent) requests() []fakeReq {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]fakeReq(nil), a.log...)
}

func (a *fakeAgent) countCommunity(c string) int {
	n := 0
	for _, r := range a.requests() {
		if r.Community == c && r.Type == gosnmp.GetRequest {
			n++
		}
	}
	return n
}

func (a *fakeAgent) serve() {
	buf := make([]byte, 65535)
	for {
		n, from, err := a.conn.ReadFrom(buf)
		if err != nil {
			return
		}
		a.handle(append([]byte(nil), buf[:n]...), from)
	}
}

func (a *fakeAgent) next(oid string, k int) []gosnmp.SnmpPDU {
	i := sort.Search(len(a.oids), func(i int) bool { return oidLess(oid, a.oids[i]) })
	var out []gosnmp.SnmpPDU
	for ; i < len(a.oids) && len(out) < k; i++ {
		out = append(out, a.vals["."+a.oids[i]])
	}
	if len(out) == 0 {
		out = append(out, gosnmp.SnmpPDU{Name: "." + strings.TrimPrefix(oid, "."), Type: gosnmp.EndOfMibView})
	}
	return out
}

func (a *fakeAgent) handle(b []byte, from net.Addr) {
	dec := &gosnmp.GoSNMP{Version: gosnmp.Version2c, Community: "x"}
	pkt, err := dec.SnmpDecodePacket(b)
	if err != nil || pkt == nil {
		return
	}
	req := fakeReq{Community: pkt.Community, Type: pkt.PDUType}
	for _, v := range pkt.Variables {
		req.OIDs = append(req.OIDs, strings.TrimPrefix(v.Name, "."))
	}
	a.mu.Lock()
	a.log = append(a.log, req)
	a.mu.Unlock()
	if !a.accept[pkt.Community] {
		return
	}
	var out []gosnmp.SnmpPDU
	switch pkt.PDUType {
	case gosnmp.GetRequest:
		for _, v := range pkt.Variables {
			if p, ok := a.vals[v.Name]; ok {
				out = append(out, p)
			} else {
				out = append(out, gosnmp.SnmpPDU{Name: v.Name, Type: gosnmp.NoSuchObject})
			}
		}
	case gosnmp.GetNextRequest:
		for _, v := range pkt.Variables {
			out = append(out, a.next(v.Name, 1)...)
		}
	case gosnmp.GetBulkRequest:
		reps := int(pkt.MaxRepetitions)
		if reps < 1 {
			reps = 1
		}
		if reps > 50 {
			reps = 50
		}
		for _, v := range pkt.Variables {
			out = append(out, a.next(v.Name, reps)...)
		}
	default: // SET and anything else is never answered; the test fails if one arrives
		a.mu.Lock()
		a.setSeen = true
		a.mu.Unlock()
		return
	}
	enc := &gosnmp.GoSNMP{Version: gosnmp.Version2c, Community: pkt.Community}
	enc.SetRequestID(pkt.RequestID - 1)
	resp, err := enc.SnmpEncodePacket(gosnmp.GetResponse, out, 0, 0)
	if err != nil {
		a.t.Logf("fake agent encode: %v", err)
		return
	}
	_, _ = a.conn.WriteTo(resp, from)
}
