import { useState, type FormEvent } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { assetsApi, type Offboarding as Ob } from "../../assetsApi";
import { useAuth } from "../../auth/context";
import { AssetStatusBadge, FormError, TextArea } from "../../components/assets";
import { Button, Card, Empty, ErrorNote, Field, Modal, PageHeader, Select, Table, Tag } from "../../components/ui";
import { errMsg, fmtDate } from "../../lib/assets";
import { useApi } from "../../lib/useApi";

function NewOffboarding({ open, onClose, onDone }: { open: boolean; onClose: () => void; onDone: (o: Ob) => void }) {
  const [f, setF] = useState({ person_email: "", person_username: "", person_name: "", department: "", leave_date: "", retrieval_due: "", notes: "" });
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const inp = (k: keyof typeof f) => ({ value: f[k], onChange: (e: { target: { value: string } }) => setF((x) => ({ ...x, [k]: e.target.value })) });
  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const o = await assetsApi.createOffboarding({ ...f, person_email: f.person_email.trim(), person_username: f.person_username.trim(), retrieval_due: f.retrieval_due || undefined });
      onDone(o);
      onClose();
    } catch (err) {
      setError(errMsg(err));
    } finally {
      setBusy(false);
    }
  }
  return (
    <Modal open={open} onClose={onClose} title="Person leaving">
      <form className="space-y-3" onSubmit={submit}>
        <p className="text-sm text-ink-2">
          Every asset assigned to this person (or in repair for them) moves to “retrieval pending” with the due date below. Give the email, the computer username, or both: owners set
          automatically from the agent are known by username only.
        </p>
        <FormError error={error} />
        <Field label="Email" id="ob-email" type="email" maxLength={320} {...inp("person_email")} />
        <Field label="Username (computer sign-in)" id="ob-user" maxLength={128} placeholder="e.g. musao or CORP\musao" {...inp("person_username")} />
        <Field label="Name (default: from their assets)" id="ob-name" maxLength={128} {...inp("person_name")} />
        <Field label="Department" id="ob-dept" maxLength={128} {...inp("department")} />
        <Field label="Leave date" id="ob-leave" type="date" required {...inp("leave_date")} />
        <Field label="Retrieval due" id="ob-due" type="date" {...inp("retrieval_due")} hint="Default: leave date + the configured number of days." />
        <TextArea label="Notes" id="ob-notes" value={f.notes} onChange={(v) => setF((x) => ({ ...x, notes: v }))} />
        <div className="flex justify-end gap-2 pt-2">
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="primary" disabled={busy || (!f.person_email.trim() && !f.person_username.trim()) || !f.leave_date}>
            {busy ? "Saving…" : "Start offboarding"}
          </Button>
        </div>
      </form>
    </Modal>
  );
}

function Detail({ id, canEdit, onChange }: { id: string; canEdit: boolean; onChange: () => void }) {
  const { data, error, reload } = useApi(() => assetsApi.offboarding(id), [id]);
  const [err, setErr] = useState<string | null>(null);
  if (!data) return <ErrorNote error={error} />;
  async function cancel() {
    const notes = window.prompt("Cancel this offboarding? Assets go back to assigned. Notes:");
    if (notes === null) return;
    try {
      await assetsApi.cancelOffboarding(id, notes);
      reload();
      onChange();
    } catch (e) {
      setErr(errMsg(e));
    }
  }
  return (
    <Card
      title={`${data.person_name || data.person_email || data.person_username}: leaving ${fmtDate(data.leave_date)}`}
      actions={canEdit && data.status === "open" && <Button onClick={cancel}>Cancel offboarding</Button>}
    >
      <ErrorNote error={err} />
      <p className="mb-3 text-sm text-ink-2">
        {[data.person_email, data.person_username && `username ${data.person_username}`].filter(Boolean).join(" · ")} {data.department && `· ${data.department}`} · retrieval due {fmtDate(data.retrieval_due)} · {data.assets_outstanding} of {data.assets_total} outstanding
        {data.notes && <span className="block whitespace-pre-wrap text-ink-3">{data.notes}</span>}
      </p>
      {(data.assets ?? []).length === 0 ? (
        <Empty>No assets were assigned to this person.</Empty>
      ) : (
        <Table head={["Asset", "Status", "Due"]}>
          {(data.assets ?? []).map((a) => (
            <tr key={a.id}>
              <td className="px-3 py-2">
                <Link to={`/it-assets/${a.id}`} className="font-medium hover:text-accent">
                  {a.display_name}
                </Link>{" "}
                <span className="text-xs text-ink-3">{[a.display_name !== a.asset_tag && a.asset_tag, a.manufacturer, a.model].filter(Boolean).join(" ")}</span>
              </td>
              <td className="px-3 py-2">
                <AssetStatusBadge status={a.status} />
              </td>
              <td className="px-3 py-2 text-xs">{a.retrieval_overdue ? <Tag tone="warn">overdue {fmtDate(a.retrieval_due)}</Tag> : fmtDate(a.retrieval_due)}</td>
            </tr>
          ))}
        </Table>
      )}
    </Card>
  );
}

export default function Offboarding() {
  const { can } = useAuth();
  const [params, setParams] = useSearchParams();
  const selected = params.get("id");
  const [status, setStatus] = useState("open");
  const [creating, setCreating] = useState(false);
  const { data, error, reload } = useApi(() => assetsApi.offboardings(status || undefined), [status]);
  return (
    <div>
      <div className="mb-1 text-xs text-ink-3">
        <Link to="/it-assets" className="hover:text-ink">
          IT assets
        </Link>{" "}
        / Offboarding
      </div>
      <PageHeader
        title="Offboarding & retrieval"
        subtitle="Mark a person as leaving: their assets go to retrieval pending; overdue retrievals are flagged and notified (source asset_lifecycle)."
        actions={can("analyst") && <Button variant="primary" onClick={() => setCreating(true)}>Person leaving</Button>}
      />
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        <Card actions={<Select label="Status" value={status} onChange={setStatus} options={[{ value: "open", label: "Open" }, { value: "completed", label: "Completed" }, { value: "cancelled", label: "Cancelled" }, { value: "", label: "All" }]} />} title="Leavers">
          <ErrorNote error={error} />
          {data && data.length === 0 ? (
            <Empty>No offboardings.</Empty>
          ) : (
            <Table head={["Person", "Leave date", "Due", "Outstanding"]}>
              {(data ?? []).map((o) => (
                <tr key={o.id} className={`cursor-pointer hover:bg-surface-2 ${selected === o.id ? "bg-surface-2" : ""}`} onClick={() => setParams({ id: o.id })}>
                  <td className="px-3 py-2">
                    <div className="font-medium">{o.person_name || o.person_email || o.person_username}</div>
                    <div className="text-[11px] text-ink-3">{[o.person_email, o.person_username].filter(Boolean).join(" · ")}</div>
                  </td>
                  <td className="px-3 py-2 text-xs">{fmtDate(o.leave_date)}</td>
                  <td className="px-3 py-2 text-xs">
                    {fmtDate(o.retrieval_due)} {o.overdue && <Tag tone="warn">overdue</Tag>}
                  </td>
                  <td className="px-3 py-2 text-xs">
                    {o.status === "open" ? `${o.assets_outstanding} / ${o.assets_total}` : <span className="capitalize text-ink-3">{o.status}</span>}
                  </td>
                </tr>
              ))}
            </Table>
          )}
        </Card>
        {selected && <Detail key={selected} id={selected} canEdit={can("analyst")} onChange={reload} />}
      </div>
      {creating && (
        <NewOffboarding
          open
          onClose={() => setCreating(false)}
          onDone={(o) => {
            setStatus("");
            reload();
            setParams({ id: o.id });
          }}
        />
      )}
    </div>
  );
}
