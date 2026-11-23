import { useState } from "react";
import { api } from "../api/client";
import { CLASSIFICATIONS, type AnomalyBlock, type AuditEvent, type AuditSearch, type PoliciesResponse, type PolicyConfig, type PolicySettings, type SecurityEventsResponse } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { EventTable } from "../components/EventTable";
import { Empty, ErrorNotice, PageHead, Panel, Pill, Updated } from "../components/ui";
import { bytes, dur, time } from "../lib/format";
import { useApi } from "../lib/useApi";

type Tab = "auth" | "denied" | "suspicious" | "integrity" | "policy";

const INTEGRITY = (e: AuditEvent) =>
  e.event_type === "file.integrity" ||
  e.event_type.startsWith("storage.replica.") ||
  e.event_type.includes("integrity") ||
  (e.reason ?? "").includes("integrity") ||
  (e.reason ?? "").includes("corrupt") ||
  (e.reason ?? "").includes("mac-invalid");

export function Security() {
  const [tab, setTab] = useState<Tab>("auth");
  const sec = useApi(() => api.get<SecurityEventsResponse>("/api/security/events", { limit: 500, critical_limit: 50 }), [], 10_000);
  const blocks = useApi(() => api.get<{ blocks: AnomalyBlock[]; scope: string }>("/api/security/anomaly-blocks"), [], 10_000);

  const tabs: { id: Tab; label: string }[] = [
    { id: "auth", label: "Authentication" },
    { id: "denied", label: "Access denied" },
    { id: "suspicious", label: "Suspicious activity" },
    { id: "integrity", label: "Integrity failures" },
    { id: "policy", label: "Policy" },
  ];
  // The general feed and the separately selected critical list, merged (newest first, no duplicates).
  const merged = new Map<number, AuditEvent>();
  for (const e of [...(sec.data?.critical ?? []), ...(sec.data?.events ?? [])]) merged.set(e.seq, e);
  const integrityEvents = [...merged.values()].sort((a, b) => b.seq - a.seq).filter(INTEGRITY);
  const critical = sec.data?.critical ?? [];
  return (
    <div className="page">
      <PageHead
        title="Security centre"
        sub={sec.data ? (sec.data.scope === "all" ? "Events from every user." : "Only your own events are visible to you.") : undefined}
      >
        <Updated at={sec.updatedAt} loading={sec.loading} />
      </PageHead>
      {blocks.data && blocks.data.blocks.length > 0 && <BlockList blocks={blocks.data.blocks} onChange={() => void blocks.reload()} />}
      <Panel
        title="Critical alerts"
        className={critical.length > 0 ? "alert-panel" : undefined}
        actions={sec.data && <span className="muted small">newest {critical.length} critical</span>}
      >
        <p className="muted small">
          Selected separately from all other events, so a flood of warnings (for example invalid tokens) cannot push a critical alert out of
          view: refresh-token reuse, integrity failures, anomaly detections, failed audit verification.
        </p>
        <ErrorNotice error={sec.error} />
        {sec.data && (critical.length === 0 ? <Empty>No critical events recorded</Empty> : <EventTable events={critical} />)}
      </Panel>
      <div className="tabs page-tabs" role="tablist">
        {tabs.map((t) => (
          <button key={t.id} role="tab" aria-selected={tab === t.id} className={tab === t.id ? "on" : ""} onClick={() => setTab(t.id)}>
            {t.label}
            {t.id === "integrity" && integrityEvents.length > 0 && <span className="count crit">{integrityEvents.length}</span>}
            {t.id === "suspicious" && blocks.data && blocks.data.blocks.length > 0 && <span className="count warn">{blocks.data.blocks.length}</span>}
          </button>
        ))}
      </div>
      {tab === "auth" && (
        <AuditQuery key="auth" title="Authentication events" query={{ event_type: "auth.*" }} note="Sign-ins, refreshes, MFA, password changes, lockouts and token reuse." />
      )}
      {tab === "denied" && <AuditQuery key="denied" title="Requests denied by policy" query={{ outcome: "denied" }} note="Every denial is an audited policy decision; the reason is the rule that denied it." />}
      {tab === "suspicious" && (
        <>
          <AuditQuery
            key="anom"
            title="Anomaly detections"
            query={{ event_type: "security.*" }}
            note="Bulk-download and credential-stuffing detections, and blocks lifted by administrators."
          />
          <AuditQuery key="lock" title="Lockouts and refresh-token reuse" query={{ event_type: "auth.*", min_severity: "warning" }} />
          {blocks.data && blocks.data.blocks.length === 0 && <p className="muted small">No active anomaly blocks.</p>}
          <ErrorNotice error={blocks.error} />
        </>
      )}
      {tab === "integrity" && (
        <Panel title="Integrity failures">
          <p className="muted small">Tampered manifests, metadata hash mismatches, corrupt or missing replicas found by downloads, scrubs and repairs.</p>
          <ErrorNotice error={sec.error} />
          {sec.data && (integrityEvents.length === 0 ? <Empty>No integrity failures recorded</Empty> : <EventTable events={integrityEvents} />)}
        </Panel>
      )}
      {tab === "policy" && <PolicyView />}
    </div>
  );
}

function AuditQuery({ title, query, note }: { title: string; query: Record<string, string>; note?: string }) {
  const q = useApi(() => api.get<AuditSearch>("/api/audit/events", { ...query, limit: 50, order: "desc" }), [JSON.stringify(query)], 10_000);
  return (
    <Panel title={title} actions={q.data && <span className="muted small">{q.data.total} total, newest 50 shown</span>}>
      {note && <p className="muted small">{note}</p>}
      <ErrorNotice error={q.error} onRetry={() => void q.reload()} />
      {q.data && (q.data.events.length === 0 ? <Empty>No events recorded</Empty> : <EventTable events={q.data.events} />)}
    </Panel>
  );
}

function BlockList({ blocks, onChange }: { blocks: AnomalyBlock[]; onChange: () => void }) {
  const { can } = useAuth();
  const [error, setError] = useState<unknown>(null);
  return (
    <Panel title="Active anomaly blocks" className="alert-panel">
      <table className="table tight">
        <thead>
          <tr>
            <th>User</th>
            <th>Reason</th>
            <th>Blocked until</th>
            <th />
          </tr>
        </thead>
        <tbody>
          {blocks.map((b) => (
            <tr key={b.actor}>
              <td>
                {b.username ?? <code>{b.actor}</code>}
              </td>
              <td>
                <code>{b.reason}</code>
              </td>
              <td>{time(b.blocked_until)}</td>
              <td>
                {can("admin") && b.user_id && (
                  <button
                    className="btn small"
                    onClick={async () => {
                      setError(null);
                      try {
                        await api.del(`/api/security/anomaly-blocks/${b.user_id}`);
                        onChange();
                      } catch (e) {
                        setError(e);
                      }
                    }}
                  >
                    Lift block
                  </button>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <ErrorNotice error={error} compact />
    </Panel>
  );
}

function PolicyView() {
  const { can } = useAuth();
  const pol = useApi(() => api.get<PoliciesResponse>("/api/security/policies"), []);
  const settings = useApi(() => api.get<PolicySettings>("/api/security/policy-settings"), []);
  return (
    <>
      <Panel title="Policy settings" actions={settings.data && <span className="muted small">version {settings.data.version}</span>}>
        <ErrorNotice error={settings.error} />
        {settings.data && <SettingsForm s={settings.data} editable={can("admin")} onSaved={() => { void settings.reload(); void pol.reload(); }} />}
      </Panel>
      <Panel title="Policy rules" actions={pol.data && <span className="muted small">{pol.data.rules.length} rules, evaluated guard, then constraint, then allow</span>}>
        <ErrorNotice error={pol.error} />
        {pol.data && (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Rule</th>
                  <th>Stage</th>
                  <th>Effect</th>
                  <th>Actions</th>
                  <th>Roles</th>
                  <th>Condition</th>
                  <th>Deny reason</th>
                </tr>
              </thead>
              <tbody>
                {pol.data.rules.map((r) => (
                  <tr key={r.id}>
                    <td>
                      <code>{r.id}</code>
                      <div className="small">{r.description}</div>
                    </td>
                    <td>{r.stage}</td>
                    <td>
                      <Pill tone={r.effect === "allow" ? "ok" : "crit"}>{r.effect}</Pill>
                    </td>
                    <td className="small">{r.actions === "*" ? "all actions" : r.actions.join(", ")}</td>
                    <td className="small">{r.roles.length ? r.roles.join(", ") : "any"}</td>
                    <td className="small">{r.condition ?? "–"}</td>
                    <td>{r.reason ? <code>{r.reason}</code> : "–"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>
    </>
  );
}

const ALL_ACTIONS = [
  "file:create", "file:list", "file:read-metadata", "file:read", "file:delete", "file:share", "file:verify", "file:repair",
  "audit:read-own", "audit:read-all", "audit:verify", "audit:checkpoint", "audit:retention",
  "dashboard:read", "storage:read", "storage:admin", "policy:read", "policy:write", "security:read",
  "kms:read", "kms:rotate", "user:list", "user:manage",
];

function SettingsForm({ s, editable, onSaved }: { s: PolicySettings; editable: boolean; onSaved: () => void }) {
  const [draft, setDraft] = useState<PolicyConfig>(s.config);
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const [saved, setSaved] = useState(false);
  const changes: Partial<PolicyConfig> = {};
  for (const k of Object.keys(draft) as (keyof PolicyConfig)[]) {
    if (JSON.stringify(draft[k]) !== JSON.stringify(s.config[k])) (changes as Record<string, unknown>)[k] = draft[k];
  }
  const dirty = Object.keys(changes).length > 0;
  const set = <K extends keyof PolicyConfig>(k: K, v: PolicyConfig[K]) => {
    setSaved(false);
    setDraft((d) => ({ ...d, [k]: v }));
  };
  const numField = (k: keyof PolicyConfig, label: string, fmt: (n: number) => string) => (
    <label className="field" key={k}>
      <span>
        {label} <span className="muted small">default {fmt(s.defaults[k] as number)}</span>
      </span>
      <input type="number" disabled={!editable} value={draft[k] as number} onChange={(e) => set(k, Number(e.target.value) as never)} />
      <span className="muted tiny">{fmt(draft[k] as number)}</span>
    </label>
  );
  return (
    <form
      onSubmit={async (e) => {
        e.preventDefault();
        setBusy(true);
        setError(null);
        try {
          await api.put<PolicySettings>("/api/security/policy-settings", { changes });
          setSaved(true);
          onSaved();
        } catch (err) {
          setError(err);
        } finally {
          setBusy(false);
        }
      }}
    >
      {!editable && <p className="muted small">Read only. Only administrators can change policy settings (with a fresh MFA check).</p>}
      {s.ignored_keys.length > 0 && <p className="warn-text small">Ignored stored keys: {s.ignored_keys.join(", ")}</p>}
      <div className="form-grid">
        <label className="field check">
          <input type="checkbox" disabled={!editable} checked={draft.require_mfa_for_login} onChange={(e) => set("require_mfa_for_login", e.target.checked)} />
          <span>Require MFA for every session (sessions without it are restricted)</span>
        </label>
        <label className="field">
          <span>Classification that needs MFA to download</span>
          <select disabled={!editable} value={draft.mfa_required_classification} onChange={(e) => set("mfa_required_classification", e.target.value as PolicyConfig["mfa_required_classification"])}>
            {CLASSIFICATIONS.map((c) => (
              <option key={c}>{c}</option>
            ))}
          </select>
        </label>
        {numField("mfa_step_up_max_age_seconds", "Step-up MFA valid for (s)", dur)}
        {numField("max_session_age_seconds", "Maximum session age (s)", dur)}
        {numField("max_downloads_in_window", "Downloads allowed per window", String)}
        {numField("max_download_bytes_in_window", "Bytes allowed per window", bytes)}
        {numField("window_seconds", "Detection window (s)", dur)}
        {numField("block_seconds", "Block duration (s)", dur)}
      </div>
      <fieldset className="actions-set" disabled={!editable}>
        <legend>Actions that need a fresh MFA check</legend>
        <div className="checks">
          {ALL_ACTIONS.map((a) => (
            <label key={a} className="check">
              <input
                type="checkbox"
                checked={draft.mfa_required_actions.includes(a)}
                onChange={(e) =>
                  set("mfa_required_actions", e.target.checked ? [...draft.mfa_required_actions, a].sort() : draft.mfa_required_actions.filter((x) => x !== a))
                }
              />
              <code>{a}</code>
            </label>
          ))}
        </div>
      </fieldset>
      <ErrorNotice error={error} compact />
      {saved && !dirty && <div className="notice notice-ok">Saved. The change is audited as policy.change.</div>}
      {editable && (
        <div className="row end">
          <button type="button" className="btn ghost" disabled={!dirty || busy} onClick={() => setDraft(s.config)}>
            Discard changes
          </button>
          <button className="btn primary" disabled={!dirty || busy}>
            {busy ? "Saving…" : `Save ${Object.keys(changes).length || ""} change${Object.keys(changes).length === 1 ? "" : "s"}`}
          </button>
        </div>
      )}
    </form>
  );
}
