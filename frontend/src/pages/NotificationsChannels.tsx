import { useState, type FormEvent } from "react";
import { ApiError } from "../api";
import { Button, Card, Empty, ErrorNote, Field, Modal, NameCell, Pill, PillRow, Table, TextCell } from "../components/ui";
import { fmtAgo } from "../lib/format";
import { useApi } from "../lib/useApi";
import { ts, useSort } from "../lib/useSort";
import { notificationsApi, type Channel, type ChannelType, type FieldSpec, type NotificationMeta } from "../notificationsApi";

const inputCls =
  "block w-full rounded border border-line bg-surface-2 px-3 py-1.5 text-sm text-ink focus:border-accent focus:outline-none focus:ring-2 focus:ring-accent/40";

function errMsg(e: unknown) {
  return e instanceof ApiError || e instanceof Error ? e.message : String(e);
}

function randomSecret() {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

function initialValues(fields: FieldSpec[], channel: Channel | null): Record<string, string> {
  const v: Record<string, string> = {};
  for (const f of fields) {
    if (f.secret) v[f.name] = "";
    else {
      const raw = channel?.config[f.name] ?? f.default ?? "";
      v[f.name] = Array.isArray(raw) ? raw.join(", ") : String(raw);
    }
  }
  return v;
}

/** "Sentrigis <no-reply@sentrigis.com>" -> "no-reply@sentrigis.com" */
function senderAddress(from: string) {
  return /<([^>]+)>/.exec(from)?.[1] ?? from;
}

function ProviderCard({
  selected,
  disabled,
  onSelect,
  title,
  badge,
  text,
}: {
  selected: boolean;
  disabled?: boolean;
  onSelect: () => void;
  title: string;
  badge?: string;
  text: string;
}) {
  return (
    <label
      className={`flex cursor-pointer items-start gap-2 rounded border p-3 text-sm ${selected ? "border-accent bg-accent/10" : "border-line"} ${disabled ? "cursor-not-allowed opacity-60" : ""}`}
    >
      <input type="radio" name="ch-provider" className="mt-1" checked={selected} disabled={disabled} onChange={onSelect} />
      <span className="min-w-0">
        <span className="flex flex-wrap items-center gap-2 font-medium text-ink">
          {title}
          {badge && <Pill tone="good">{badge}</Pill>}
        </span>
        <span className="mt-0.5 block text-xs text-ink-3">{text}</span>
      </span>
    </label>
  );
}

function ChannelDialog({
  meta,
  channel,
  open,
  onClose,
  onSaved,
}: {
  meta: NotificationMeta;
  channel: Channel | null;
  open: boolean;
  onClose: () => void;
  onSaved: (msg: string) => void;
}) {
  const [type, setType] = useState<ChannelType>(channel?.type ?? "teams");
  const spec = meta.channel_types.find((t) => t.type === type)!;
  const [name, setName] = useState(channel?.name ?? "");
  const [values, setValues] = useState<Record<string, string>>(() => initialValues(spec.fields, channel));
  const [generated, setGenerated] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [savedId, setSavedId] = useState<string | null>(channel?.id ?? null);
  const [testNote, setTestNote] = useState<{ ok: boolean; text: string } | null>(null);
  const provider = values.provider || "sentrigis";
  const isEmail = type === "email";
  const limit = meta.sentrigis_email.daily_limit;
  // The provider is chosen with the two cards below, not as a drop-down.
  const visible = spec.fields.filter((f) => (!f.provider || f.provider === provider) && !(isEmail && f.name === "provider"));

  function changeType(t: ChannelType) {
    setType(t);
    setValues(initialValues(meta.channel_types.find((x) => x.type === t)!.fields, null));
    setGenerated(null);
    setTestNote(null);
  }

  /** Create the channel, or update it once it exists. Returns its id, or null when it could not be saved. */
  async function save(): Promise<string | null> {
    setBusy(true);
    setError(null);
    const config: Record<string, unknown> = {};
    const secrets: Record<string, string> = {};
    for (const f of visible) {
      const v = (values[f.name] ?? "").trim();
      if (f.secret) {
        if (v) secrets[f.name] = v;
      } else if (f.kind === "list") config[f.name] = v.split(/[,;\s]+/).filter(Boolean);
      else if (f.kind === "int") config[f.name] = v ? Number(v) : undefined;
      else config[f.name] = v;
    }
    if (isEmail) config.provider = provider;
    try {
      if (savedId) {
        await notificationsApi.updateChannel(savedId, {
          name: name.trim(),
          config: Object.keys(config).length ? config : undefined,
          secrets,
        });
        onSaved(`Channel "${name}" updated.`);
        return savedId;
      }
      const created = await notificationsApi.createChannel({ name: name.trim(), type, config, secrets });
      setSavedId(created.id);
      onSaved(`Channel "${name}" created. Use "Send test" to verify it.`);
      return created.id;
    } catch (err) {
      setError(errMsg(err));
      return null;
    } finally {
      setBusy(false);
    }
  }

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (await save()) onClose();
  }

  /** Save (the test goes to the saved channel), then send one test email and show the result here. */
  async function sendTest() {
    setTestNote(null);
    const id = await save();
    if (!id) return;
    setBusy(true);
    try {
      const r = await notificationsApi.testChannel(id);
      setTestNote(
        r.ok
          ? { ok: true, text: "Test email sent. Check the inbox of the recipients (and the spam folder)." }
          : { ok: false, text: `Test email not sent: ${r.delivery.last_error ?? "unknown error"}` },
      );
    } catch (err) {
      setTestNote({ ok: false, text: errMsg(err) });
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal open={open} onClose={onClose} title={channel ? `Edit ${channel.name}` : "Add notification channel"}>
      <form className="max-h-[70vh] space-y-3 overflow-y-auto pr-1" onSubmit={submit}>
        {error && (
          <div role="alert" className="rounded border border-sev-critical/60 bg-sev-critical/10 px-3 py-2 text-sm">
            {error}
          </div>
        )}
        {!channel && (
          <div>
            <label htmlFor="ch-type" className="mb-1 block text-sm font-medium text-ink-2">
              Type
            </label>
            <select id="ch-type" className={inputCls} value={type} onChange={(e) => changeType(e.target.value as ChannelType)}>
              {meta.channel_types.map((t) => (
                <option key={t.type} value={t.type}>
                  {t.label}
                </option>
              ))}
            </select>
            <p className="mt-1 text-xs text-ink-3">{spec.description}</p>
          </div>
        )}
        <Field label="Name" id="ch-name" required maxLength={128} value={name} onChange={(e) => setName(e.target.value)} />
        {isEmail && (
          <fieldset>
            <legend className="mb-1 block text-sm font-medium text-ink-2">Send with</legend>
            {provider !== "sentrigis" && provider !== "smtp" && (
              <p className="mb-2 text-xs text-sev-medium">This channel uses an older setup that is no longer offered. Choose one of the two options below.</p>
            )}
            <div className="grid gap-2 sm:grid-cols-2">
              <ProviderCard
                selected={provider === "sentrigis"}
                disabled={!meta.sentrigis_email.available}
                onSelect={() => setValues({ ...values, provider: "sentrigis" })}
                title="Sentrigis"
                badge="Recommended"
                text={`No setup. Sent from ${meta.sentrigis_email.sender ? senderAddress(meta.sentrigis_email.sender) : "no-reply@sentrigis.com"}.`}
              />
              <ProviderCard
                selected={provider === "smtp"}
                onSelect={() => setValues({ ...values, provider: "smtp" })}
                title="Your own mail server (SMTP)"
                text="Send from your own domain, e.g. alerts@yourcompany.com. Needs server details."
              />
            </div>
            {!meta.sentrigis_email.available && (
              <p className="mt-1 text-xs text-sev-medium">Sending with Sentrigis is not available on this server. Use your own mail server.</p>
            )}
          </fieldset>
        )}
        {visible.map((f) => {
          const id = `ch-${f.name}`;
          const saved = channel?.secret_hints[f.name];
          if (f.kind === "select") {
            return (
              <div key={f.name}>
                <label htmlFor={id} className="mb-1 block text-sm font-medium text-ink-2">
                  {f.label}
                </label>
                <select id={id} className={inputCls} value={values[f.name]} onChange={(e) => setValues({ ...values, [f.name]: e.target.value })}>
                  {f.options.map((o) => (
                    <option key={o} value={o}>
                      {o}
                    </option>
                  ))}
                </select>
                {f.help && <p className="mt-1 text-xs text-ink-3">{f.help}</p>}
              </div>
            );
          }
          return (
            <div key={f.name}>
              <Field
                label={f.label + (f.required && !saved ? " *" : "")}
                id={id}
                type={f.secret ? "password" : f.kind === "int" ? "number" : "text"}
                autoComplete={f.secret ? "new-password" : "off"}
                required={f.required && !saved && f.secret ? true : f.required && !f.secret}
                placeholder={saved ? `Saved: ${saved} (leave blank to keep)` : undefined}
                hint={
                  f.help +
                  (isEmail && provider === "sentrigis" && f.name === "to_addresses"
                    ? ` Up to ${limit} alert emails a day for your organisation. Alerts over the limit still appear in the console and the notification log.`
                    : "") +
                  (f.name === "password" ? " Microsoft 365: turn on authenticated SMTP for this mailbox first." : "") +
                  (f.kind === "url" && spec.allowed_hosts.length ? ` Allowed hosts: ${spec.allowed_hosts.join(", ")}.` : "") +
                  (f.secret ? " Stored encrypted; never shown again after saving." : "")
                }
                value={values[f.name] ?? ""}
                onChange={(e) => setValues({ ...values, [f.name]: e.target.value })}
              />
              {f.name === "signing_secret" && (
                <div className="mt-1 flex items-center gap-2">
                  <Button
                    onClick={() => {
                      const s = randomSecret();
                      setValues({ ...values, signing_secret: s });
                      setGenerated(s);
                    }}
                  >
                    Generate
                  </Button>
                  {generated && (
                    <code className="break-all rounded bg-surface-2 px-1.5 py-0.5 text-[11px]" aria-label="Generated signing secret">
                      {generated}
                    </code>
                  )}
                </div>
              )}
            </div>
          );
        })}
        {generated && <p className="text-xs text-sev-medium">Copy the signing secret to your receiver now: it cannot be displayed after saving.</p>}
        {testNote && (
          <div
            role="status"
            className={`rounded border px-3 py-2 text-sm ${testNote.ok ? "border-good/60 bg-good/10" : "border-sev-critical/60 bg-sev-critical/10"}`}
          >
            {testNote.text}
          </div>
        )}
        <div className="flex flex-wrap items-center justify-end gap-2 pt-2">
          {isEmail && (
            <Button onClick={() => void sendTest()} disabled={busy || !name.trim()}>
              Send a test email
            </Button>
          )}
          <div className="flex-1" />
          <Button onClick={onClose}>{savedId && !channel ? "Close" : "Cancel"}</Button>
          <Button type="submit" variant="primary" disabled={busy || !name.trim()}>
            {busy ? "Saving…" : savedId ? "Save" : "Create channel"}
          </Button>
        </div>
      </form>
    </Modal>
  );
}

function destination(c: Channel): string {
  const hints = Object.values(c.secret_hints).filter((h) => h.startsWith("http"));
  if (c.type === "email") {
    const to = (c.config.to_addresses as string[] | undefined) ?? [];
    return `${c.config.provider === "sentrigis" ? "Sentrigis" : "SMTP"} → ${to.join(", ")}`;
  }
  return hints[0] ?? "••••••";
}

export default function NotificationsChannels({ meta, isAdmin, onChange }: { meta: NotificationMeta; isAdmin: boolean; onChange: () => void }) {
  const { data, error, reload } = useApi(notificationsApi.channels, []);
  const [editing, setEditing] = useState<Channel | null>(null);
  const [creating, setCreating] = useState(false);
  const [notice, setNotice] = useState<{ ok: boolean; text: string } | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const label = (t: string) => meta.channel_types.find((x) => x.type === t)?.label ?? t;
  const sorted = useSort(
    data,
    {
      name: (c) => c.name,
      type: (c) => label(c.type),
      destination: (c) => destination(c),
      status: (c) => (c.enabled ? 0 : 1),
      last_test: (c) => ts(c.last_test_at),
    },
    { key: "name", dir: "asc" },
    { last_test: "desc" },
  );

  async function act(id: string, fn: () => Promise<string>) {
    setBusy(id);
    setNotice(null);
    try {
      setNotice({ ok: true, text: await fn() });
    } catch (e) {
      setNotice({ ok: false, text: errMsg(e) });
    } finally {
      setBusy(null);
      reload();
      onChange();
    }
  }

  return (
    <div>
      <ErrorNote error={error} />
      {notice && (
        <div
          role="status"
          className={`mb-3 rounded border px-3 py-2 text-sm ${notice.ok ? "border-good/60 bg-good/10" : "border-sev-critical/60 bg-sev-critical/10"}`}
        >
          {notice.text}
        </div>
      )}
      <Card
        title="Channels"
        actions={
          isAdmin && (
            <Button variant="primary" onClick={() => setCreating(true)}>
              Add channel
            </Button>
          )
        }
      >
        {data && data.length === 0 ? (
          <Empty>No channels yet.{isAdmin ? " Add a Teams, Slack, email or webhook channel to start." : ""}</Empty>
        ) : (
          <Table
            tableId="notifications-channels"
            head={[{ label: "Channel", sort: "name", w: 240 }, { label: "Destination", sort: "destination", w: 280 }, { label: "Status", sort: "status", w: 110 }, { label: "Last test", sort: "last_test", w: 160 }, ...(isAdmin ? [{ label: "Actions", srOnly: true, w: 320 }] : [])]}
            sort={sorted.sort}
            onSort={sorted.onSort}
          >
            {sorted.rows.map((c) => (
              <tr key={c.id}>
                <td className="px-3 py-2"><NameCell name={c.name} sub={label(c.type)} /></td>
                <td className="px-3 py-2"><TextCell mono title={destination(c)}>{destination(c)}</TextCell></td>
                <td className="px-3 py-2"><PillRow>{c.enabled ? <Pill tone="good">On</Pill> : <Pill>Off</Pill>}</PillRow></td>
                <td className="px-3 py-2">
                  {c.last_test_at ? (
                    <PillRow>
                      <Pill tone={c.last_test_status === "ok" ? "good" : "high"}>{c.last_test_status === "ok" ? "OK" : "Failed"}</Pill>
                      <span className="text-ink-3">{fmtAgo(c.last_test_at)}</span>
                    </PillRow>
                  ) : (
                    <TextCell muted>Never</TextCell>
                  )}
                </td>
                {isAdmin && (
                  <td className="px-3 py-2">
                    <div className="flex flex-wrap gap-2">
                      <Button
                        disabled={busy === c.id}
                        onClick={() =>
                          act(c.id, async () => {
                            const r = await notificationsApi.testChannel(c.id);
                            if (!r.ok) throw new Error(`Test failed: ${r.delivery.last_error ?? "unknown error"}`);
                            return `Test notification sent to "${c.name}".`;
                          })
                        }
                      >
                        {busy === c.id ? "Sending…" : "Send test"}
                      </Button>
                      <Button onClick={() => setEditing(c)}>Edit</Button>
                      <Button
                        onClick={() =>
                          act(c.id, async () => {
                            await notificationsApi.updateChannel(c.id, { enabled: !c.enabled });
                            return `Channel "${c.name}" ${c.enabled ? "disabled" : "enabled"}.`;
                          })
                        }
                      >
                        {c.enabled ? "Disable" : "Enable"}
                      </Button>
                      <Button
                        variant="danger"
                        onClick={() => {
                          if (window.confirm(`Delete channel "${c.name}"? Rules will stop sending to it.`))
                            act(c.id, async () => {
                              await notificationsApi.deleteChannel(c.id);
                              return `Channel "${c.name}" deleted.`;
                            });
                        }}
                      >
                        Delete
                      </Button>
                    </div>
                  </td>
                )}
              </tr>
            ))}
          </Table>
        )}
      </Card>
      {creating && (
        <ChannelDialog meta={meta} channel={null} open onClose={() => setCreating(false)} onSaved={(t) => { setNotice({ ok: true, text: t }); reload(); }} />
      )}
      {editing && (
        <ChannelDialog
          key={editing.id}
          meta={meta}
          channel={editing}
          open
          onClose={() => setEditing(null)}
          onSaved={(t) => {
            setNotice({ ok: true, text: t });
            reload();
          }}
        />
      )}
    </div>
  );
}
