package actions

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/model"
	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/state"
)

// ----------------------------------------------------------------------------- fakes

type fakeServices struct {
	svcs     map[string]*model.Service
	setErr   error
	stopErr  error
	calls    []string
	noChange bool // Start/Stop do not change the status (timeouts)
}

func (f *fakeServices) find(name string) *model.Service {
	for n, s := range f.svcs {
		if strings.EqualFold(n, name) {
			return s
		}
	}
	return nil
}

func (f *fakeServices) List() ([]model.Service, error) {
	var out []model.Service
	for _, s := range f.svcs {
		out = append(out, *s)
	}
	return out, nil
}

func (f *fakeServices) Query(name string) (model.Service, error) {
	if s := f.find(name); s != nil {
		return *s, nil
	}
	return model.Service{}, ErrNotFound
}

func (f *fakeServices) Start(name string) error {
	f.calls = append(f.calls, "start "+name)
	if !f.noChange {
		f.find(name).Status = "running"
	}
	return nil
}

func (f *fakeServices) Stop(name string) error {
	f.calls = append(f.calls, "stop "+name)
	if f.stopErr != nil {
		return f.stopErr
	}
	if !f.noChange {
		f.find(name).Status = "stopped"
	}
	return nil
}

func (f *fakeServices) SetStartType(name, t string) error {
	f.calls = append(f.calls, "set "+name+" "+t)
	if f.setErr != nil {
		return f.setErr
	}
	f.find(name).StartType = t
	return nil
}

type regVal struct {
	key, name string
}

type fakeRegistry struct {
	keys    map[string]bool
	vals    map[regVal]uint32
	failSet string // value name whose SetDWORD fails
}

func newRegistry() *fakeRegistry {
	return &fakeRegistry{keys: map[string]bool{USBStorKey: true}, vals: map[regVal]uint32{{USBStorKey, "Start"}: 3}}
}

func (r *fakeRegistry) GetDWORD(key, name string) (uint32, bool, error) {
	v, ok := r.vals[regVal{key, name}]
	return v, ok, nil
}

func (r *fakeRegistry) SetDWORD(key, name string, v uint32) error {
	if name == r.failSet {
		return errors.New("access denied")
	}
	// CreateKey creates intermediate keys too.
	for k := key; ; {
		r.keys[k] = true
		i := strings.LastIndex(k, `\`)
		if i < 0 || !strings.HasPrefix(k, RemovableStorageKey) || k == RemovableStorageKey {
			break
		}
		k = k[:i]
	}
	r.vals[regVal{key, name}] = v
	return nil
}

func (r *fakeRegistry) DeleteValue(key, name string) error {
	delete(r.vals, regVal{key, name})
	return nil
}

func (r *fakeRegistry) KeyExists(key string) (bool, error) { return r.keys[key], nil }

func (r *fakeRegistry) DeleteKeyIfEmpty(key string) error {
	for v := range r.vals {
		if v.key == key {
			return nil
		}
	}
	for k := range r.keys {
		if strings.HasPrefix(k, key+`\`) {
			return nil
		}
	}
	delete(r.keys, key)
	return nil
}

type fakePrograms struct {
	progs   map[string]Program
	exit    int
	runErr  error
	ran     []Cmd
	removes bool // a successful run removes the entry
}

func (f *fakePrograms) Lookup(source, key string) (Program, error) {
	p, ok := f.progs[source+"|"+key]
	if !ok {
		return Program{}, ErrNotFound
	}
	return p, nil
}

func (f *fakePrograms) Run(ctx context.Context, c Cmd) (int, string, error) {
	f.ran = append(f.ran, c)
	if f.runErr != nil {
		return -1, "", f.runErr
	}
	if f.removes {
		for k := range f.progs {
			delete(f.progs, k)
		}
	}
	return f.exit, "", nil
}

func newManager(t *testing.T) (*Manager, *fakeServices, *fakeRegistry, *fakePrograms) {
	t.Helper()
	old := supportedOS
	supportedOS = true
	t.Cleanup(func() { supportedOS = old })
	svcs := &fakeServices{svcs: map[string]*model.Service{
		"Spooler":    {Name: "Spooler", DisplayName: "Print Spooler", Status: "running", StartType: "auto"},
		"WSearch":    {Name: "WSearch", DisplayName: "Windows Search", Status: "running", StartType: "auto_delayed"},
		"RpcSs":      {Name: "RpcSs", DisplayName: "Remote Procedure Call (RPC)", Status: "running", StartType: "auto"},
		"CNAPPAgent": {Name: "CNAPPAgent", DisplayName: "CNAPP Endpoint Agent", Status: "running", StartType: "auto"},
		"TermService": {Name: "TermService", DisplayName: "Remote Desktop Services", Status: "running",
			StartType: "manual"},
		"Fax": {Name: "Fax", DisplayName: "Fax", Status: "stopped", StartType: "disabled"},
	}}
	reg := newRegistry()
	progs := &fakePrograms{progs: map[string]Program{}, removes: true}
	dir := t.TempDir()
	m := &Manager{Paths: state.Paths{StateDir: filepath.Join(dir, "state"), Custom: true}, Services: svcs, Registry: reg,
		Programs: progs, SystemRoot: `C:\Windows`, AgentDir: `C:\Program Files\CNAPP Agent`,
		ServiceWait: 50 * time.Millisecond, VerifyWait: 20 * time.Millisecond, PollEvery: time.Millisecond,
		UninstallTime: time.Second}
	return m, svcs, reg, progs
}

func cmd(t, id string, p map[string]any) model.Command {
	return model.Command{ID: id, Type: t, Params: p}
}

// ----------------------------------------------------------------------------- params

func TestParseServiceParams(t *testing.T) {
	ok := []map[string]any{
		{"service": "Spooler", "action": "stop"},
		{"service": "CDPUserSvc_1a2b3", "action": "disable"},
		{"service": "WSearch", "action": "restore", "restore_to": "auto_delayed"},
		{"service": "Spooler", "action": "restore", "restore_to": nil},
	}
	for _, p := range ok {
		if _, err := ParseServiceParams(p); err != nil {
			t.Errorf("%v: %v", p, err)
		}
	}
	bad := []map[string]any{
		{"service": "", "action": "stop"},
		{"service": `..\evil`, "action": "stop"},
		{"service": "Spooler", "action": "delete"},
		{"service": "Spooler"},
		{"service": 7, "action": "stop"},
		{"service": "Spooler", "action": "stop", "restore_to": "auto"},
		{"service": "Spooler", "action": "restore", "restore_to": "disabled"},
		{"service": "Spooler", "action": "restore", "restore_to": "boot"},
	}
	for _, p := range bad {
		if _, err := ParseServiceParams(p); err == nil {
			t.Errorf("%v: accepted", p)
		}
	}
}

func TestParseUninstallParams(t *testing.T) {
	good := map[string]any{"identifier": "{23170F69-40C1-2702-2409-000001000000}", "source": "registry_hklm64",
		"name": "7-Zip 24.09 (x64 edition)", "version": "24.09.00.0"}
	if _, err := ParseUninstallParams(good); err != nil {
		t.Fatal(err)
	}
	for name, p := range map[string]map[string]any{
		"per-user":       {"identifier": "Zoom", "source": "registry_user", "name": "Zoom"},
		"backslash":      {"identifier": `a\b`, "source": "registry_hklm64", "name": "x"},
		"no name":        {"identifier": "x", "source": "registry_hklm64", "name": ""},
		"agent itself":   {"identifier": "{11111111-1111-1111-1111-111111111111}", "source": "registry_hklm64", "name": "CNAPP Endpoint Agent"},
		"control char":   {"identifier": "a\x01b", "source": "registry_hklm64", "name": "x"},
		"unknown source": {"identifier": "x", "source": "applications", "name": "x"},
	} {
		if _, err := ParseUninstallParams(p); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestUnsupportedOS(t *testing.T) {
	m, _, _, _ := newManager(t)
	supportedOS = false
	r := m.Execute(context.Background(), cmd(BlockUSBStorage, "c1", nil))
	if r.Status != "rejected" || !strings.Contains(r.Output, "unsupported on this OS") {
		t.Fatalf("%+v", r)
	}
	if _, _, ok := m.USBStatus(); ok {
		t.Fatal("USB status reported on an unsupported OS")
	}
	if l, _ := m.ListServices(); l != nil {
		t.Fatal("services reported on an unsupported OS")
	}
}

// ----------------------------------------------------------------------------- services

func TestProtectedServices(t *testing.T) {
	for _, n := range []string{"rpcss", "CNAPPAgent", "WinDefend", "mpssvc", "EventLog", "Winmgmt", "BFE"} {
		if !IsProtected(n, false) {
			t.Errorf("%s not protected", n)
		}
	}
	if IsProtected("Spooler", true) || IsProtected("TermService", false) || !IsProtected("termservice", true) {
		t.Fatal("wrong protection")
	}
	m, svcs, _, _ := newManager(t)
	for _, c := range []model.Command{
		cmd(ManageService, "a", map[string]any{"service": "rpcss", "action": "stop"}),
		cmd(ManageService, "b", map[string]any{"service": "CNAPPAgent", "action": "disable"}),
	} {
		r := m.Execute(context.Background(), c)
		if r.Status != "rejected" || r.Data["error_code"] != "ERR_PROTECTED_SERVICE" {
			t.Fatalf("%+v", r)
		}
	}
	m.RemoteActive = func() bool { return true }
	if r := m.Execute(context.Background(), cmd(ManageService, "c", map[string]any{"service": "TermService", "action": "stop"})); r.Status != "rejected" ||
		!strings.Contains(r.Output, "remote session") {
		t.Fatalf("%+v", r)
	}
	if len(svcs.calls) != 0 {
		t.Fatalf("protected services touched: %v", svcs.calls)
	}
	// Starting a protected service is allowed.
	svcs.svcs["RpcSs"].Status = "stopped"
	if r := m.Execute(context.Background(), cmd(ManageService, "d", map[string]any{"service": "RpcSs", "action": "start"})); r.Status != "succeeded" {
		t.Fatalf("%+v", r)
	}
}

func TestStopStartService(t *testing.T) {
	m, svcs, _, _ := newManager(t)
	ctx := context.Background()
	r := m.Execute(ctx, cmd(ManageService, "1", map[string]any{"service": "spooler", "action": "stop"}))
	if r.Status != "succeeded" || r.Data["status"] != "stopped" || r.Data["service"] != "Spooler" {
		t.Fatalf("%+v", r)
	}
	r = m.Execute(ctx, cmd(ManageService, "2", map[string]any{"service": "Spooler", "action": "start"}))
	if r.Status != "succeeded" || svcs.svcs["Spooler"].Status != "running" {
		t.Fatalf("%+v", r)
	}
	if r = m.Execute(ctx, cmd(ManageService, "3", map[string]any{"service": "Fax", "action": "start"})); r.Status != "failed" ||
		!strings.Contains(r.Output, "disabled") {
		t.Fatalf("%+v", r)
	}
	if r = m.Execute(ctx, cmd(ManageService, "4", map[string]any{"service": "NoSuch", "action": "stop"})); r.Status != "failed" ||
		!strings.Contains(r.Output, "does not exist") {
		t.Fatalf("%+v", r)
	}
	svcs.noChange = true
	if r = m.Execute(ctx, cmd(ManageService, "5", map[string]any{"service": "Spooler", "action": "stop"})); r.Status != "failed" ||
		!strings.Contains(r.Output, "did not stop") {
		t.Fatalf("%+v", r)
	}
}

func TestDisableRestoreServiceIsExact(t *testing.T) {
	m, svcs, _, _ := newManager(t)
	ctx := context.Background()
	r := m.Execute(ctx, cmd(ManageService, "d1", map[string]any{"service": "WSearch", "action": "disable"}))
	if r.Status != "succeeded" || r.Data["previous_start_type"] != "auto_delayed" || svcs.svcs["WSearch"].StartType != "disabled" {
		t.Fatalf("%+v", r)
	}
	// A second disable keeps the original value.
	r = m.Execute(ctx, cmd(ManageService, "d2", map[string]any{"service": "WSearch", "action": "disable"}))
	if r.Status != "succeeded" || r.Data["previous_start_type"] != "auto_delayed" {
		t.Fatalf("%+v", r)
	}
	// The saved value survives a restart of the agent (new Manager, same state dir).
	m2 := &Manager{Paths: m.Paths, Services: m.Services, Registry: m.Registry, Programs: m.Programs,
		ServiceWait: m.ServiceWait, PollEvery: m.PollEvery}
	r = m2.Execute(ctx, cmd(ManageService, "r1", map[string]any{"service": "wsearch", "action": "restore", "restore_to": "manual"}))
	if r.Status != "succeeded" || svcs.svcs["WSearch"].StartType != "auto_delayed" || r.Data["restored_start_type"] != "auto_delayed" {
		t.Fatalf("restore used %v: %+v", svcs.svcs["WSearch"].StartType, r)
	}
	// Nothing saved any more: restore uses the server's value, else fails.
	svcs.svcs["WSearch"].StartType = "disabled"
	r = m.Execute(ctx, cmd(ManageService, "r2", map[string]any{"service": "WSearch", "action": "restore"}))
	if r.Status != "failed" || !strings.Contains(r.Output, "no saved startup type") {
		t.Fatalf("%+v", r)
	}
	r = m.Execute(ctx, cmd(ManageService, "r3", map[string]any{"service": "WSearch", "action": "restore", "restore_to": "manual"}))
	if r.Status != "succeeded" || svcs.svcs["WSearch"].StartType != "manual" {
		t.Fatalf("%+v", r)
	}
}

func TestDisableFailureForgetsSavedValue(t *testing.T) {
	m, svcs, _, _ := newManager(t)
	svcs.setErr = errors.New("access denied")
	r := m.Execute(context.Background(), cmd(ManageService, "d", map[string]any{"service": "Spooler", "action": "disable"}))
	if r.Status != "failed" {
		t.Fatalf("%+v", r)
	}
	st, _ := m.load()
	if len(st.Services) != 0 {
		t.Fatalf("saved value kept after a failed disable: %+v", st)
	}
}

// ----------------------------------------------------------------------------- uninstall

func TestPlanAndMsiexecArgs(t *testing.T) {
	m, _, _, _ := newManager(t)
	code := "{23170F69-40C1-2702-2409-000001000000}"
	c, method, err := m.Plan(Program{Key: code, WindowsInstaller: true, UninstallString: "MsiExec.exe /I" + code})
	if err != nil || method != MethodMSI || c.Path != `C:\Windows/System32/msiexec.exe` && c.Path != `C:\Windows\System32\msiexec.exe` {
		t.Fatalf("%+v %s %v", c, method, err)
	}
	if !reflect.DeepEqual(c.Args, []string{"/x", code, "/qn", "/norestart"}) || c.CmdLine != "" {
		t.Fatalf("args %v", c.Args)
	}
	cases := []struct {
		q, exe, err string
	}{
		{`"C:\Program Files\Foo\uninst.exe" /S`, `C:\Program Files\Foo\uninst.exe`, ""},
		{`C:\Program Files\Foo Bar\unins000.exe /VERYSILENT /SUPPRESSMSGBOXES`, `C:\Program Files\Foo Bar\unins000.exe`, ""},
		{`MsiExec.exe /X{AAAAAAAA-0000-0000-0000-000000000000} /qn`, `C:\Windows`, ""},
		{`cmd.exe /c del C:\x`, "", "use a script"},
		{`"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -File x.ps1`, "", "use a script"},
		{`uninst.exe /S`, "", "absolute path"},
		{`"C:\Foo\setup.bat" /S`, "", "use a script"},
		{`"C:\Foo\unins.exe /S`, "", "unterminated"},
	}
	for _, tc := range cases {
		c, method, err := m.Plan(Program{Key: "Foo", QuietUninstallString: tc.q})
		if tc.err != "" {
			if err == nil || !strings.Contains(err.Error(), tc.err) {
				t.Errorf("%s: err %v", tc.q, err)
			}
			continue
		}
		if err != nil || method != MethodQuiet || !strings.HasPrefix(c.Path, tc.exe) || c.CmdLine != tc.q {
			t.Errorf("%s: %+v %v", tc.q, c, err)
		}
	}
	// MSI flag without a product-code key falls back to the quiet string; nothing at all is refused.
	if _, _, err := m.Plan(Program{Key: "Foo", WindowsInstaller: true, UninstallString: `C:\Foo\uninst.exe`}); !errors.Is(err, ErrNoSilentUninstaller) {
		t.Fatalf("%v", err)
	}
}

func TestExitMeaning(t *testing.T) {
	for code, want := range map[int]struct {
		status string
		reboot bool
	}{0: {"succeeded", false}, 3010: {"succeeded", true}, 1641: {"succeeded", true}, 1605: {"succeeded", false},
		1614: {"succeeded", false}, 1603: {"failed", false}, 1618: {"failed", false}, 1: {"failed", false}} {
		st, meaning, reboot := ExitMeaning(code)
		if st != want.status || reboot != want.reboot || meaning == "" {
			t.Errorf("%d: %s %v", code, st, reboot)
		}
	}
}

func TestUninstall(t *testing.T) {
	m, _, _, progs := newManager(t)
	ctx := context.Background()
	code := "{23170F69-40C1-2702-2409-000001000000}"
	progs.progs["registry_hklm64|"+code] = Program{Key: code, DisplayName: "7-Zip 24.09", DisplayVersion: "24.09", WindowsInstaller: true}
	params := map[string]any{"identifier": code, "source": "registry_hklm64", "name": "7-Zip 24.09"}
	r := m.Execute(ctx, cmd(UninstallSoftware, "u1", params))
	if r.Status != "succeeded" || !r.Refresh || r.Data["method"] != MethodMSI || r.Data["verified"] != true || *r.ExitCode != 0 {
		t.Fatalf("%+v", r)
	}
	if len(progs.ran) != 1 || progs.ran[0].Args[0] != "/x" {
		t.Fatalf("%+v", progs.ran)
	}
	// Gone already: success without running anything.
	r = m.Execute(ctx, cmd(UninstallSoftware, "u2", params))
	if r.Status != "succeeded" || r.Data["already_removed"] != true || len(progs.ran) != 1 {
		t.Fatalf("%+v", r)
	}
	// Exit 0 but still registered (and no restart pending): failed.
	progs.removes = false
	progs.progs["registry_hklm64|"+code] = Program{Key: code, DisplayName: "7-Zip 24.09", WindowsInstaller: true}
	if r = m.Execute(ctx, cmd(UninstallSoftware, "u3", params)); r.Status != "failed" || !strings.Contains(r.Output, "still registered") {
		t.Fatalf("%+v", r)
	}
	// 3010: succeeded, restart required, may stay listed.
	progs.exit = 3010
	if r = m.Execute(ctx, cmd(UninstallSoftware, "u4", params)); r.Status != "succeeded" || r.Data["reboot_required"] != true {
		t.Fatalf("%+v", r)
	}
	progs.exit = 1603
	if r = m.Execute(ctx, cmd(UninstallSoftware, "u5", params)); r.Status != "failed" || *r.ExitCode != 1603 {
		t.Fatalf("%+v", r)
	}
	// The display name changed since the inventory: refused.
	params["name"] = "Something else"
	if r = m.Execute(ctx, cmd(UninstallSoftware, "u6", params)); r.Status != "rejected" {
		t.Fatalf("%+v", r)
	}
}

func TestUninstallRefusals(t *testing.T) {
	m, _, _, progs := newManager(t)
	ctx := context.Background()
	progs.progs["registry_hklm64|Foo"] = Program{Key: "Foo", DisplayName: "Foo", UninstallString: `C:\Foo\uninst.exe`}
	r := m.Execute(ctx, cmd(UninstallSoftware, "a", map[string]any{"identifier": "Foo", "source": "registry_hklm64", "name": "Foo"}))
	if r.Status != "rejected" || !strings.Contains(r.Output, "no silent uninstaller") || r.Data["error_code"] != "ERR_NO_SILENT_UNINSTALLER" {
		t.Fatalf("%+v", r)
	}
	// The agent under another name, recognised by its directory.
	progs.progs["registry_hklm64|Agent"] = Program{Key: "Agent", DisplayName: "Endpoint thing",
		QuietUninstallString: `"C:\Program Files\CNAPP Agent\cnapp-agent.exe" uninstall`}
	r = m.Execute(ctx, cmd(UninstallSoftware, "b", map[string]any{"identifier": "Agent", "source": "registry_hklm64", "name": "Endpoint thing"}))
	if r.Status != "rejected" || !strings.Contains(r.Output, "never uninstalls itself") {
		t.Fatalf("%+v", r)
	}
	if len(progs.ran) != 0 {
		t.Fatalf("ran %+v", progs.ran)
	}
	progs.runErr = context.DeadlineExceeded
	progs.progs["registry_hklm64|Bar"] = Program{Key: "Bar", DisplayName: "Bar", QuietUninstallString: `"C:\Bar\u.exe" /S`}
	m.UninstallTime = time.Nanosecond
	r = m.Execute(ctx, cmd(UninstallSoftware, "c", map[string]any{"identifier": "Bar", "source": "registry_hklm64", "name": "Bar"}))
	if r.Status != "failed" || !strings.Contains(r.Output, "did not finish") {
		t.Fatalf("%+v", r)
	}
}

// ----------------------------------------------------------------------------- USB

func TestUSBBlockUnblockRestoresExactly(t *testing.T) {
	m, _, reg, _ := newManager(t)
	ctx := context.Background()
	// A pre-existing policy value that must survive unchanged.
	reg.keys[RemovableStorageKey] = true
	reg.vals[regVal{RemovableStorageKey, "Deny_All"}] = 0
	before := map[regVal]uint32{}
	for k, v := range reg.vals {
		before[k] = v
	}
	keysBefore := map[string]bool{}
	for k := range reg.keys {
		keysBefore[k] = true
	}
	if data, _, _ := m.USBStatus(); data["blocked"] != false {
		t.Fatalf("%+v", data)
	}
	r := m.Execute(ctx, cmd(BlockUSBStorage, "b1", nil))
	if r.Status != "succeeded" || r.Data["blocked"] != true {
		t.Fatalf("%+v", r)
	}
	if reg.vals[regVal{USBStorKey, "Start"}] != 4 || reg.vals[regVal{RemovableDisksKey, "Deny_Read"}] != 1 ||
		reg.vals[regVal{RemovableDisksKey, "Deny_Write"}] != 1 || reg.vals[regVal{RemovableDisksKey, "Deny_Execute"}] != 1 {
		t.Fatalf("%+v", reg.vals)
	}
	data, detail, _ := m.USBStatus()
	if data["blocked_by_agent"] != true || !strings.Contains(detail, "CNAPP") {
		t.Fatalf("%+v %s", data, detail)
	}
	// Blocking again re-applies without overwriting the saved originals.
	if r = m.Execute(ctx, cmd(BlockUSBStorage, "b2", nil)); r.Status != "succeeded" || !strings.Contains(r.Output, "already blocked") {
		t.Fatalf("%+v", r)
	}
	if r = m.Execute(ctx, cmd(UnblockUSBStorage, "u1", nil)); r.Status != "succeeded" || r.Data["blocked"] != false {
		t.Fatalf("%+v", r)
	}
	if !reflect.DeepEqual(reg.vals, before) || !reflect.DeepEqual(reg.keys, keysBefore) {
		t.Fatalf("not restored exactly:\n%v\n%v\nkeys %v\n%v", reg.vals, before, reg.keys, keysBefore)
	}
	if r = m.Execute(ctx, cmd(UnblockUSBStorage, "u2", nil)); r.Status != "succeeded" || !strings.Contains(r.Output, "not blocked") {
		t.Fatalf("%+v", r)
	}
}

func TestUSBUnblockWithoutSavedValues(t *testing.T) {
	m, _, reg, _ := newManager(t)
	reg.vals[regVal{USBStorKey, "Start"}] = 4 // blocked by someone else
	r := m.Execute(context.Background(), cmd(UnblockUSBStorage, "u", nil))
	if r.Status != "failed" || !strings.Contains(r.Output, "not by this agent") || reg.vals[regVal{USBStorKey, "Start"}] != 4 {
		t.Fatalf("%+v", r)
	}
}

func TestUSBBlockRollsBackOnFailure(t *testing.T) {
	m, _, reg, _ := newManager(t)
	reg.failSet = "Deny_Write"
	r := m.Execute(context.Background(), cmd(BlockUSBStorage, "b", nil))
	if r.Status != "failed" || !strings.Contains(r.Output, "previous values were restored") {
		t.Fatalf("%+v", r)
	}
	if reg.vals[regVal{USBStorKey, "Start"}] != 3 || reg.keys[RemovableDisksKey] {
		t.Fatalf("not rolled back: %+v %+v", reg.vals, reg.keys)
	}
	if st, _ := m.load(); st.USB != nil {
		t.Fatal("saved values kept after rollback")
	}
}

func TestUSBNoUSBStorKey(t *testing.T) {
	m, _, reg, _ := newManager(t)
	delete(reg.keys, USBStorKey)
	delete(reg.vals, regVal{USBStorKey, "Start"})
	r := m.Execute(context.Background(), cmd(BlockUSBStorage, "b", nil))
	if r.Status != "succeeded" || reg.keys[USBStorKey] {
		t.Fatalf("created the driver key: %+v", r)
	}
	if r = m.Execute(context.Background(), cmd(UnblockUSBStorage, "u", nil)); r.Status != "succeeded" || len(reg.vals) != 0 {
		t.Fatalf("%+v %+v", r, reg.vals)
	}
}

func TestSavedFileCorrupt(t *testing.T) {
	m, _, _, _ := newManager(t)
	if err := os.MkdirAll(m.Paths.StateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(m.Paths.StateDir, FileName), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if r := m.Execute(context.Background(), cmd(BlockUSBStorage, "b", nil)); r.Status != "failed" || !strings.Contains(r.Output, "corrupt") {
		t.Fatalf("%+v", r)
	}
}
