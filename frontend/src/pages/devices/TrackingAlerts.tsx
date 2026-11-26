import { Switch } from "../../components/Switch";
import { Card } from "../../components/ui";
import type { TrackingSettings, TrackingSettingsPatch } from "../../trackingApi";

const DAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
const inputCls = "rounded border border-line bg-surface-2 px-2 py-1 text-sm text-ink focus:border-accent focus:outline-none focus:ring-2 focus:ring-accent/40";

function Row({ title, hint, on, label, onChange, children }: {
  title: string; hint: string; on: boolean; label: string; onChange: (v: boolean) => void; children?: React.ReactNode;
}) {
  return (
    <div className="border-b border-line py-3 last:border-b-0">
      <div className="flex items-center justify-between gap-4">
        <div>
          <div className="text-sm font-medium text-ink">{title}</div>
          <div className="text-xs text-ink-3">{hint}</div>
        </div>
        <Switch on={on} label={label} onChange={onChange} />
      </div>
      {on && children && <div className="mt-2 flex flex-wrap items-center gap-3 text-sm text-ink-2">{children}</div>}
    </div>
  );
}

/** Settings > Device tracking > Alerts. Edits the page's draft (saved by the page's single Save bar); the alerts
 * only run while tracking is on. */
export default function TrackingAlerts({ s, draft, set }: {
  s: TrackingSettings; draft: TrackingSettingsPatch; set: (p: TrackingSettingsPatch) => void;
}) {
  const v = { ...s, ...draft } as TrackingSettings;
  const notSeenOn = v.alert_not_seen_days != null;
  const weekdays = v.after_hours_weekdays;

  return (
    <Card title="Alerts" className="mb-4">
      <p className="mb-1 text-sm text-ink-3">
        Alerts appear in the computer&apos;s location history and in notifications (source &ldquo;Device tracking&rdquo;), so rules can send them to email, Teams, Slack or a webhook.
        They only run while tracking is on.
      </p>
      <Row title="Outside allowed countries" label="Alert outside allowed countries" on={v.alert_outside_countries}
        hint="A computer connects from a country that is not on the allowed list (needs at least one allowed country). High severity."
        onChange={(on) => set({ alert_outside_countries: on })} />
      <Row title="Not seen for several days" label="Alert when not seen" on={notSeenOn}
        hint="A computer has not checked in for this long. Once per absence."
        onChange={(on) => set({ alert_not_seen_days: on ? 7 : null })}>
        <label className="flex items-center gap-2">After
          <input type="number" min={1} max={90} aria-label="Days not seen" value={v.alert_not_seen_days ?? 7} className={`${inputCls} w-20`}
            onChange={(e) => set({ alert_not_seen_days: Math.min(90, Math.max(1, Number(e.target.value) || 1)) })} />
          days (1 to 90)
        </label>
      </Row>
      <Row title="Away from offices after hours" label="Alert away after hours" on={v.alert_after_hours}
        hint="A computer is away from every office during these hours. Once per computer per night, in the last office's time zone (else the organisation's)."
        onChange={(on) => set({ alert_after_hours: on })}>
        <label className="flex items-center gap-2">From
          <input type="time" aria-label="After hours start" value={v.after_hours_start} className={inputCls}
            onChange={(e) => e.target.value && set({ after_hours_start: e.target.value })} /></label>
        <label className="flex items-center gap-2">to
          <input type="time" aria-label="After hours end" value={v.after_hours_end} className={inputCls}
            onChange={(e) => e.target.value && set({ after_hours_end: e.target.value })} /></label>
        <span className="flex flex-wrap gap-2" role="group" aria-label="Nights it applies">
          {DAYS.map((d, i) => (
            <label key={d} className="flex items-center gap-1 text-xs">
              <input type="checkbox" checked={weekdays.includes(i)}
                onChange={() => set({ after_hours_weekdays: weekdays.includes(i) ? weekdays.filter((x) => x !== i) : [...weekdays, i].sort() })} />
              {d}
            </label>
          ))}
        </span>
        <span className="text-xs text-ink-3">A night belongs to the day it starts on.</span>
      </Row>
      <Row title="Hardware changed" label="Alert when hardware changed" on={v.alert_hardware_changed}
        hint="Serial number or system model changed, memory decreased, or a disk was removed or changed size."
        onChange={(on) => set({ alert_hardware_changed: on })} />
      <Row title="Agent stopped or removed" label="Alert when the agent stops" on={v.alert_agent_stopped}
        hint="The agent was reporting every minute and has been silent for over 2 hours (not for removed computers). Laptops that sleep overnight can trigger it."
        onChange={(on) => set({ alert_agent_stopped: on })} />
      <Row title="Lock automatically outside allowed countries" label="Turn on lost mode automatically" on={v.auto_lost_mode_outside_countries}
        hint="Turns on lost mode (the screen shows a message, a contact number and, if set, an IT support email). It never wipes the computer, and happens once until lost mode is cleared. Shown in the audit log as an automatic action."
        onChange={(on) => set({ auto_lost_mode_outside_countries: on })}>
        <label className="flex items-center gap-2">Contact phone shown on the screen
          <input type="tel" aria-label="Contact phone" value={v.auto_lost_mode_phone ?? ""} className={`${inputCls} w-48`} maxLength={32}
            placeholder="+234 800 000 0000" onChange={(e) => set({ auto_lost_mode_phone: e.target.value })} />
        </label>
        <label className="flex items-center gap-2">IT support email (optional)
          <input type="email" aria-label="IT support email" value={v.auto_lost_mode_email ?? ""} className={`${inputCls} w-64`} maxLength={100}
            placeholder="itsupport@yourcompany.com" onChange={(e) => set({ auto_lost_mode_email: e.target.value || null })} />
        </label>
      </Row>
    </Card>
  );
}
