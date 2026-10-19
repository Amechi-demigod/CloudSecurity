//go:build e2e_broken

package main

// e2eBrokenBuild makes every command except `version` exit with an error. It
// is only compiled with -tags e2e_broken, to build a release that passes the
// pre-flight check but fails its post-update health check (CI rollback test).
const e2eBrokenBuild = true
