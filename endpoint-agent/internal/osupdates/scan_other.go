//go:build !windows

package osupdates

import (
	"context"

	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/model"
)

// Supported reports whether this OS has a report (macOS / Linux: later).
const Supported = false

// Scan is not available on this OS.
func Scan(context.Context) (model.OSUpdateReport, error) {
	return model.OSUpdateReport{}, ErrUnsupported
}
