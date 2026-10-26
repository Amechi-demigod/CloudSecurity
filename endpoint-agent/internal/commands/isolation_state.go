package commands

// isolated tracks the current host isolation state for the agent process.
// It is toggled by isolateHost()/restoreHost() implementations.
var isolated bool

// Isolated reports whether the host is currently isolated.
func Isolated() bool { return isolated }
