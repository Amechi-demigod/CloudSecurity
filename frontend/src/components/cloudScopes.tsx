import { useState, type FormEvent } from "react";
import { ApiError } from "../api";
import { CLOUD_NAME, CLOUD_ROLE, CLOUD_SCOPE } from "../lib/cloudSetup";
import { fmtAgo, fmtTime } from "../lib/format";
import { useApi } from "../lib/useApi";
import { ts, useSort } from "../lib/useSort";
import { orgApi, type CloudScope, type Provider } from "../orgApi";
import { Button, ErrorNote, Field, Modal, Table, Tag } from "./ui";

function errMsg(e: unknown) {
  return e instanceof ApiError ? e.message : e instanceof Error ? e.message : String(e);
}

/** "89ca222c-22d3-…-d1b026a98de8" */
const shortId = (id: string) => (id.length > 24 ? `${id.slice(0, 8)}-…-${id.slice(-12)}` : id);

function status(s: CloudScope) {
  const failed = s.last_scan_status === "failed";
  if (!s.configured) {
    return (
      <span>
        <Tag>Not scanned</Tag>
        {failed && <span className="ml-1.5 text-xs text-sev-high">last scan failed</span>}
      </span>
    );
  }
  return (
    <span>
      <Tag tone="good">Scanned</Tag>
      {failed && <span className="ml-1.5 text-xs text-sev-high">last scan failed</span>}
    </span>
  );
}

/** Every subscription / account / project known for a cloud, with Remove (admins). */
export function ScopeList({ provider, onChanged }: { provider: Provider; onChanged?: () => void }) {
  const { data, error, loading, reload } = useApi(() => orgApi.connectorScopes(provider), [provider]);
  const [removing, setRemoving] = useState<CloudScope | null>(null);
  const [one] = CLOUD_SCOPE[provider];
  const noun = one.charAt(0).toUpperCase() + one.slice(1);
  const sorted = useSort(
    data,
    {
      id: (s) => s.id,
      status: (s) => (s.configured ? 1 : 0) + (s.last_scan_status === "failed" ? -0.5 : 0),
      resources: (s) => s.resources,
      last_scanned: (s) => ts(s.last_scanned),
    },
    { key: "id", dir: "asc" },
    { resources: "desc", last_scanned: "desc" },
    `${provider}sort`,
  );

  return (
    <div className="mt-4 border-t border-line px-1 pt-4" data-testid={`scopes-${provider}`}>
      <h3 className="mb-1 text-[13px] font-semibold text-ink">{noun}s known to Sentrigis</h3>
      <p className="mb-3 text-xs text-ink-3">
        The ones you scan, plus any that only still have data (for example from a failed first scan).
      </p>
      <ErrorNote error={error} />
      <Table
        head={[{ label: noun, sort: "id" }, { label: "Status", sort: "status" }, { label: "Resources", sort: "resources" }, { label: "Last scanned", sort: "last_scanned" }, { label: "Remove", srOnly: true }]}
        sort={sorted.sort}
        onSort={sorted.onSort}
        loading={loading}
        rowCount={data?.length ?? 0}
        empty={<p className="py-3 text-center text-sm text-ink-3">No {one}s yet.</p>}
      >
        {sorted.rows.map((s) => (
          <tr key={s.id}>
            <td className="px-3 py-2 font-mono text-xs" title={s.id}>
              {s.id.length > 40 ? shortId(s.id) : s.id}
            </td>
            <td className="px-3 py-2">{status(s)}</td>
            <td className="px-3 py-2 text-ink-2">
              {s.resources.toLocaleString()}
              {s.removed_resources > 0 && <span className="ml-1 text-xs text-ink-3">+ {s.removed_resources} removed</span>}
            </td>
            <td className="px-3 py-2 text-xs text-ink-2">
              {s.last_scanned ? <span title={fmtTime(s.last_scanned)}>{fmtAgo(s.last_scanned)}</span> : "—"}
            </td>
            <td className="px-3 py-2 text-right">
              <Button variant="danger" onClick={() => setRemoving(s)}>
                Remove
              </Button>
            </td>
          </tr>
        ))}
      </Table>
      {removing && (
        <RemoveScopeDialog
          provider={provider}
          scope={removing}
          onClose={() => setRemoving(null)}
          onRemoved={() => {
            setRemoving(null);
            reload();
            onChanged?.();
          }}
        />
      )}
    </div>
  );
}

function RemoveScopeDialog({ provider, scope, onClose, onRemoved }: { provider: Provider; scope: CloudScope; onClose: () => void; onRemoved: () => void }) {
  const [one] = CLOUD_SCOPE[provider];
  const need = scope.id.slice(0, 8);
  const [typed, setTyped] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const total = scope.resources + scope.removed_resources;

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await orgApi.removeConnectorScope(provider, scope.id, typed.trim());
      onRemoved();
    } catch (err) {
      setError(errMsg(err));
      setBusy(false);
    }
  }

  return (
    <Modal open onClose={onClose} title={`Remove ${one} ${shortId(scope.id)}?`}>
      <form onSubmit={submit} className="space-y-3 text-sm">
        <ErrorNote error={error} />
        <p>{scope.configured ? "Sentrigis stops scanning it." : "Sentrigis does not scan it any more."}</p>
        <p>
          Its {total.toLocaleString()} {total === 1 ? "resource" : "resources"} and their findings are deleted now. This cannot be undone.
        </p>
        <p className="text-ink-3">
          Your {CLOUD_NAME[provider]} permissions are not changed; remove the {CLOUD_ROLE[provider]} role in your cloud yourself if you no longer want Sentrigis to have access.
        </p>
        <Field
          id="confirm-scope"
          label={`Type the first 8 characters of the ${one} ID to confirm`}
          value={typed}
          onChange={(e) => setTyped(e.target.value)}
          placeholder={need}
          autoComplete="off"
        />
        <div className="flex justify-end gap-2 pt-1">
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="danger" disabled={busy || typed.trim().toLowerCase() !== need.toLowerCase()}>
            {busy ? "Removing…" : `Remove ${one}`}
          </Button>
        </div>
      </form>
    </Modal>
  );
}
