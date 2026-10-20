package scripts

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"time"
)

// OSRunner runs scripts with the platform interpreter, a timeout that kills
// the whole process tree, and capped output. The agent service runs it as
// LocalSystem (Windows) / root (macOS).
type OSRunner struct{}

// Run executes the script.
func (OSRunner) Run(ctx context.Context, s RunSpec) RunResult {
	name, args, err := interpreter(s.Interpreter, s.ScriptPath)
	if err != nil {
		return RunResult{Err: err}
	}
	ctx, cancel := context.WithTimeout(ctx, s.Timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = s.Dir
	cmd.Env = append(baseEnv(), s.Env...)
	cmd.Stdin = nil
	var stdout, stderr = &capped{n: MaxStreamBytes}, &capped{n: MaxStreamBytes}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	prepare(cmd)
	cmd.WaitDelay = 5 * time.Second
	err = cmd.Run()
	r := RunResult{Stdout: stdout.buf.Bytes(), Stderr: stderr.buf.Bytes(), Truncated: stdout.truncated || stderr.truncated}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		r.TimedOut, r.ExitCode = true, -1
		return r
	}
	var ee *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &ee):
		r.ExitCode = ee.ExitCode()
	default:
		r.Err = err
	}
	return r
}

// baseEnv is the service environment without any CNAPP_* variables, so only
// the validated parameters can appear under that prefix.
func baseEnv() []string {
	var out []string
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(strings.ToUpper(kv), "CNAPP_") {
			out = append(out, kv)
		}
	}
	return out
}
