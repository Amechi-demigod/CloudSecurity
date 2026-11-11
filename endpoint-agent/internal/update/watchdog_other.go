//go:build !linux

package update

func startWatchdogUnit(string, []string) (bool, error) { return false, nil }
