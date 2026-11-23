import { useState } from "react";
import { api } from "../api/client";
import type { AuditEvent, AuditSearch, Checkpoint, VerifyChainReport } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { EventTable } from "../components/EventTable";
import { Drawer, Empty, ErrorNotice, Hash, KV, PageHead, Panel, Pill, outcomeTone, severityTone } from "../components/ui";
import { num, time } from "../lib/format";
import { useApi } from "../lib/useApi";

interface Filters {
  actor: string;
  event_type: string;
  action: string;
  resource_id: string;
  outcome: string;
  severity: string;
  from: string;
  to: string;
  request_id: string;
  order: "desc" | "asc";
}
const EMPTY: Filters = { actor: "", event_type: "", action: "", resource_id: "", outcome: "", severity: "", from: "", to: "", request_id: "", order: "desc" };
const PAGE = 50;

/** datetime-local value (local time) → ISO UTC string the API expects. */
function toIso(v: string): string | undefined {
  if (!v) return undefined;
  const d = new Date(v);
  return Number.isNaN(d.getTime()) ? undefined : d.toISOString();
}

export function Audit() {
  const { me, can } = useAuth();
  const readAll = can("auditor", "admin");
  const [draft, setDraft] = useState<Filters>(EMPTY);
  const [filters, setFilters] = useState<Filters>(EMPTY);
  const [mine, setMine] = useState(!readAll);
  const [offset, setOffset] = useState(0);
  const [selected, setSelected] = useState<AuditEvent | null>(null);

  const query = {
    ...Object.fromEntries(Object.entries(filters).filter(([k, v]) => v && k !== "from" && k !== "to")),
    from: toIso(filters.from),
    to: toIso(filters.to),
    actor: mine ? me?.audit_pseudonym : filters.actor || undefined,
    limit: PAGE,
    offset,
  };
  const q = useApi(() => api.get<AuditSearch>("/api/audit/events", query), [JSON.stringify(query)]);
  const set = (k: keyof Filters) => (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) => setDraft((d) => ({ ...d, [k]: e.target.value }));

  return (
    <div className="page">
      <PageHead
        title="Audit explorer"
        sub={
          readAll
            ? "Hash-chained, append-only log. Actors are keyed pseudonyms, never usernames."
            : "You can see only your own events. Actors are keyed pseudonyms, never usernames."
        }
      />
      {can("auditor", "admin") && <ChainTools />}

      <Panel title="Search">
        <form
          className="filters"
          onSubmit={(e) => {
            e.preventDefault();
            setOffset(0);
            setFilters(draft);
          }}
        >
          <label className="field">
            <span>Event type</span>
            <input value={draft.event_type} onChange={set("event_type")} placeholder="file.download or file.*" list="event-types" />
            <datalist id="event-types">
              {["auth.*", "authz.*", "file.*", "storage.*", "audit.*", "security.*", "policy.*", "admin.*"].map((x) => (
                <option key={x} value={x} />
              ))}
            </datalist>
          </label>
          <label className="field">
            <span>Action</span>
            <input value={draft.action} onChange={set("action")} placeholder="file:read" />
          </label>
          <label className="field">
            <span>Outcome</span>
            <select value={draft.outcome} onChange={set("outcome")}>
              <option value="">any</option>
              {["success", "failure", "denied", "error"].map((o) => (
                <option key={o}>{o}</option>
              ))}
            </select>
          </label>
          <label className="field">
            <span>Severity</span>
            <select value={draft.severity} onChange={set("severity")}>
              <option value="">any</option>
              {["info", "warning", "critical"].map((o) => (
                <option key={o}>{o}</option>
              ))}
            </select>
          </label>
          <label className="field">
            <span>Actor pseudonym</span>
            <input value={mine ? me?.audit_pseudonym ?? "" : draft.actor} onChange={set("actor")} placeholder="u_…" disabled={mine} className="mono" />
          </label>
          <label className="field">
            <span>File or resource ID</span>
            <input value={draft.resource_id} onChange={set("resource_id")} className="mono" />
          </label>
          <label className="field">
            <span>Request ID</span>
            <input value={draft.request_id} onChange={set("request_id")} className="mono" />
          </label>
          <label className="field">
            <span>From</span>
            <input type="datetime-local" step={1} value={draft.from} onChange={set("from")} />
          </label>
          <label className="field">
            <span>To (exclusive)</span>
            <input type="datetime-local" step={1} value={draft.to} onChange={set("to")} />
          </label>
          <label className="field">
            <span>Order</span>
            <select value={draft.order} onChange={set("order")}>
              <option value="desc">newest first</option>
              <option value="asc">oldest first</option>
            </select>
          </label>
          <div className="filter-actions">
            <label className="check">
              <input
                type="checkbox"
                checked={mine}
                disabled={!readAll}
                onChange={(e) => {
                  setMine(e.target.checked);
                  setOffset(0);
                }}
              />
              <span>My events only{!readAll && " (enforced by the server for your role)"}</span>
            </label>
            <button
              type="button"
              className="btn ghost"
              onClick={() => {
                setDraft(EMPTY);
                setFilters(EMPTY);
                setOffset(0);
              }}
            >
              Clear filters
            </button>
            <button className="btn primary">Search</button>
          </div>
        </form>
      </Panel>

      <Panel
        title={q.data ? `${num(q.data.total)} events (${q.data.scope === "all" ? "all actors" : "your own"})` : "Events"}
        actions={
          q.data && (
            <div className="row">
              <span className="muted small">
                {q.data.total === 0 ? 0 : offset + 1}–{Math.min(offset + PAGE, q.data.total)}
              </span>
              <button className="btn small" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE))}>
                Previous
              </button>
              <button className="btn small" disabled={offset + PAGE >= q.data.total} onClick={() => setOffset(offset + PAGE)}>
                Next
              </button>
            </div>
          )
        }
      >
        <ErrorNotice error={q.error} onRetry={() => void q.reload()} />
        {q.data && (q.data.events.length === 0 ? <Empty>No events match these filters</Empty> : <EventTable events={q.data.events} onSelect={setSelected} selected={selected?.seq} chain />)}
        {q.data && q.data.events.length > 1 && (
          <p className="muted small">
            Chain link: each event stores the hash of the one before it (prev_hash). Colour chips are derived from the hash, so
            consecutive rows show a matching pair when no events between them are filtered out. Use Verify chain for the
            cryptographic check.
          </p>
        )}
      </Panel>

      {selected && <EventDrawer ev={selected} onClose={() => setSelected(null)} />}
    </div>
  );
}

function EventDrawer({ ev, onClose }: { ev: AuditEvent; onClose: () => void }) {
  // Re-read by seq so the drawer shows what the server holds now.
  const q = useApi(() => api.get<AuditEvent>(`/api/audit/events/${ev.seq}`), [ev.seq]);
  const e = q.data ?? ev;
  return (
    <Drawer title={`Event ${e.seq}`} onClose={onClose}>
      <ErrorNotice error={q.error} compact />
      <KV
        rows={[
          ["Seq", <span className="mono">{e.seq}</span>],
          ["Event ID", <Hash value={e.id} n={16} />],
          ["Time (UTC)", <span className="mono">{e.ts}</span>],
          ["Local time", time(e.ts)],
          ["Event type", <code>{e.event_type}</code>],
          ["Action", e.action ? <code>{e.action}</code> : "–"],
          ["Outcome", <Pill tone={outcomeTone(e.outcome)}>{e.outcome}</Pill>],
          ["Severity", <Pill tone={severityTone(e.severity)}>{e.severity}</Pill>],
          ["Reason", e.reason ? <code>{e.reason}</code> : "–"],
          ["Actor", <Hash value={e.actor} n={20} />],
          ["Actor role", e.actor_role ?? "–"],
          ["Resource", e.resource_type ? <span>{e.resource_type} <Hash value={e.resource_id} n={12} /></span> : "–"],
          ["Request ID", <Hash value={e.request_id} n={20} />],
          ["Source network", e.source_net ?? "–"],
        ]}
      />
      <h3>Chain</h3>
      <KV
        rows={[
          ["prev_hash", <span className="hash"><code className="wrap-hash">{e.prev_hash}</code></span>],
          ["hash", <span className="hash"><code className="wrap-hash">{e.hash}</code></span>],
        ]}
      />
      <h3>Details</h3>
      {Object.keys(e.details ?? {}).length === 0 ? <Empty>No details recorded</Empty> : <pre className="json">{JSON.stringify(e.details, null, 2)}</pre>}
    </Drawer>
  );
}

function ChainTools() {
  const { can } = useAuth();
  const [report, setReport] = useState<VerifyChainReport | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [fromSeq, setFromSeq] = useState("");
  const [toSeq, setToSeq] = useState("");
  const cps = useApi(() => api.get<{ checkpoints: Checkpoint[] }>("/api/audit/checkpoints", { limit: 20 }), []);

  async function run(name: string, fn: () => Promise<void>) {
    setBusy(name);
    setError(null);
    try {
      await fn();
    } catch (e) {
      setError(e);
    } finally {
      setBusy(null);
    }
  }

  return (
    <div className="grid-2">
      <Panel title="Chain verification">
        <form
          className="row wrap"
          onSubmit={(e) => {
            e.preventDefault();
            void run("verify", async () => {
              const body: Record<string, unknown> = { check_anchors: true };
              if (fromSeq) body.from_seq = Number(fromSeq);
              if (toSeq) body.to_seq = Number(toSeq);
              setReport(await api.post<VerifyChainReport>("/api/audit/verify", body));
            });
          }}
        >
          <label className="inline-field">
            <span>From seq</span>
            <input type="number" min={1} value={fromSeq} onChange={(e) => setFromSeq(e.target.value)} placeholder="first" />
          </label>
          <label className="inline-field">
            <span>To seq</span>
            <input type="number" min={1} value={toSeq} onChange={(e) => setToSeq(e.target.value)} placeholder="last" />
          </label>
          <button className="btn primary" disabled={!!busy}>
            {busy === "verify" ? "Verifying…" : "Verify chain"}
          </button>
        </form>
        <ErrorNotice error={error} compact />
        {report && (
          <div className={`verdict ${report.ok ? "verdict-ok" : "verdict-bad"}`}>
            <div className="verdict-head">
              <Pill tone={report.ok ? "ok" : "crit"}>{report.ok ? "chain intact" : "chain broken"}</Pill>
              <span>
                {num(report.events_checked)} events checked (seq {report.first_seq ?? "–"} to {report.last_seq ?? "–"}), {report.checkpoints_checked}{" "}
                checkpoints, {report.anchors_checked} anchors, {report.duration_ms.toFixed(0)} ms
              </span>
            </div>
            <div className="small">
              Head hash <Hash value={report.head_hash} n={16} swatch />
            </div>
            {report.findings.length > 0 && (
              <table className="table tight">
                <thead>
                  <tr>
                    <th>Finding</th>
                    <th className="num">Seq</th>
                    <th>Detail</th>
                  </tr>
                </thead>
                <tbody>
                  {report.findings.map((f, i) => (
                    <tr key={i}>
                      <td>
                        <code>{f.type}</code>
                      </td>
                      <td className="num">{f.seq ?? "–"}</td>
                      <td className="small">{f.detail ?? ""}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
            {report.findings_truncated && <p className="warn-text small">More findings exist; narrow the range.</p>}
          </div>
        )}
      </Panel>
      <Panel
        title="Signed checkpoints"
        actions={
          can("admin") && (
            <button
              className="btn small"
              disabled={!!busy}
              onClick={() => void run("cp", async () => { await api.post<Checkpoint>("/api/audit/checkpoints"); await cps.reload(); })}
            >
              {busy === "cp" ? "Creating…" : "Create checkpoint"}
            </button>
          )
        }
      >
        <ErrorNotice error={cps.error} compact />
        {cps.data && cps.data.checkpoints.length === 0 && <Empty>No checkpoints yet</Empty>}
        {cps.data && cps.data.checkpoints.length > 0 && (
          <div className="table-wrap">
            <table className="table tight">
              <thead>
                <tr>
                  <th className="num">Seq</th>
                  <th>Head hash</th>
                  <th>Kind</th>
                  <th>Created</th>
                  <th>Anchored on</th>
                </tr>
              </thead>
              <tbody>
                {cps.data.checkpoints.map((c) => (
                  <tr key={c.id}>
                    <td className="num mono">{c.seq}</td>
                    <td>
                      <Hash value={c.head_hash} n={10} swatch />
                    </td>
                    <td>{c.kind}</td>
                    <td className="nowrap">{time(c.ts)}</td>
                    <td className="small">
                      {Object.entries(c.anchors).map(([p, ok]) => (
                        <Pill key={p} tone={ok ? "ok" : "crit"}>
                          {p}
                        </Pill>
                      ))}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>
    </div>
  );
}
