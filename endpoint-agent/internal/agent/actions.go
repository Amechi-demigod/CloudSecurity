package agent

import (
	"context"
	"log/slog"

	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/commands"
	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/model"
)

// endpointAction runs manage_service / uninstall_software / block_usb_storage
// / unblock_usb_storage (internal/actions). After an uninstall the agent checks
// in once the result is reported, so the console's software list is current.
func (a *Agent) endpointAction(ctx context.Context, c model.Command) commands.Outcome {
	if a.Actions == nil {
		return commands.Outcome{Status: "rejected", Output: "endpoint actions are not available in this agent mode"}
	}
	r := a.Actions.Execute(ctx, c)
	out := commands.Outcome{Status: r.Status, Output: r.Output, ExitCode: r.ExitCode, ResultData: r.Data}
	if r.Refresh {
		out.After = func() {
			if err := a.CheckIn(ctx); err != nil {
				slog.Warn("check-in after uninstall failed", "err", err)
			}
		}
	}
	return out
}

// addActionsInventory adds the services inventory and the USB storage state
// (posture check usb_storage, "info": the console's blocked / allowed) to a
// check-in. Windows only; nothing is added elsewhere.
func (a *Agent) addActionsInventory(r *model.Report) {
	if a.Actions == nil {
		return
	}
	if list, err := a.Actions.ListServices(); err != nil {
		if r.Errors == nil {
			r.Errors = map[string]string{}
		}
		r.Errors["services"] = err.Error()
	} else if list != nil {
		r.Services = list
	}
	if data, detail, ok := a.Actions.USBStatus(); ok {
		r.Posture["usb_storage"] = model.Check(model.StatusInfo, detail, data)
	}
}
