package netscan

// Diag is the "network" section of collector diagnostics: which OS APIs the
// scan can use here and the last scan's summary. It never contains secrets
// (no credentials, communities or targets of a scan - only counts).
type Diag struct {
	ICMPAvailable bool         `json:"icmp_available"` // IcmpSendEcho2 (iphlpapi)
	ARPAvailable  bool         `json:"arp_available"`  // SendARP (iphlpapi)
	DHCPAvailable bool         `json:"dhcp_available"` // dhcpsapi.dll DHCP Server Management API
	LastScan      *DiagSummary `json:"last_scan"`
}

// DiagSummary is the last scan's outcome.
type DiagSummary struct {
	ScanID    string   `json:"scan_id"`
	Addresses int      `json:"addresses"`
	Alive     int      `json:"alive"`
	SNMP      int      `json:"snmp"`
	DurationS int      `json:"duration_s"`
	Batches   int      `json:"batches"`
	Errors    []string `json:"errors"`
}

// Diagnostics reports API availability and the last scan summary.
func Diagnostics() Diag {
	d := Diag{ICMPAvailable: icmpAvailable(), ARPAvailable: arpAvailable(), DHCPAvailable: dhcpAvailable()}
	if r := LastScan(); r != nil {
		d.LastScan = &DiagSummary{ScanID: r.ScanID, Addresses: r.Addresses, Alive: r.Alive, SNMP: r.SNMP,
			DurationS: r.DurationS, Batches: r.Batches, Errors: r.Errors}
	}
	return d
}
