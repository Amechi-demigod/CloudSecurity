//go:build !windows

package commands

// isolateHost returns an outcome indicating host isolation is unsupported on this platform.
func isolateHost() Outcome {
	return Outcome{Status: "rejected", Output: "host isolation unsupported on this platform"}
}

// restoreHost returns an outcome indicating host restore is unsupported on this platform.
func restoreHost() Outcome {
	return Outcome{Status: "rejected", Output: "host isolation restore unsupported on this platform"}
}
