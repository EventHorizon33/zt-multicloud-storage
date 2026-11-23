import { useState } from "react";
import { api } from "../api/client";
import { CLASSIFICATIONS, KMS_PURPOSES, type AdminUser, type Classification, type KmsKey, type MfaEnrollmentCode, type Role } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { CopyButton, Empty, ErrorNotice, Hash, PageHead, Panel, Pill, statusTone } from "../components/ui";
import { time } from "../lib/format";
import { useApi, type ApiState } from "../lib/useApi";

/** The server refuses audit-pseudonym rotation (403 pseudonym-key-rotation-disabled), so it is not offered. */
const ROTATABLE = KMS_PURPOSES.filter((p) => p !== "audit-pseudonym");

export function Admin() {
  const { can, me } = useAuth();
  const admin = can("admin");
  // Auditors hold kms:read but not user:list (they work with audit pseudonyms only), so the
  // directory is neither requested nor shown for them.
  const users = useApi(
    () => (admin ? api.get<{ users: AdminUser[] }>("/api/admin/users") : Promise.resolve({ users: [] as AdminUser[] })),
    [admin],
  );
  const keys = useApi(() => api.get<{ keys: KmsKey[] }>("/api/admin/kms/keys"), []);
  const [editing, setEditing] = useState<string | null>(null);

  return (
    <div className="page">
      <PageHead
        title={admin ? "Administration" : "Keys"}
        sub={
          admin
            ? "Role changes need a fresh MFA check. Administrators never see file names or content. Audit pseudonyms are mapped to accounts only through the audited lookup."
            : "Key metadata, read only. Auditors work with audit pseudonyms; there is no user directory for this role."
        }
      />
      {admin && (
      <Panel title={`Users${users.data ? ` (${users.data.users.length})` : ""}`}>
        <ErrorNotice error={users.error} onRetry={() => void users.reload()} />
        {users.data && users.data.users.length === 0 && <Empty />}
        {users.data && users.data.users.length > 0 && (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>User</th>
                  <th>Role</th>
                  <th>Clearance</th>
                  <th>State</th>
                  <th>MFA</th>
                  <th className="num">Sessions</th>
                  <th>Network allow list</th>
                  {admin && <th />}
                </tr>
              </thead>
              <tbody>
                {users.data.users.map((u) => (
                  <UserRow
                    key={u.id}
                    u={u}
                    self={u.id === me?.user.id}
                    admin={admin}
                    open={editing === u.id}
                    onToggle={() => setEditing(editing === u.id ? null : u.id)}
                    onChanged={() => void users.reload()}
                  />
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>
      )}
      <KmsPanel keys={keys} admin={admin} />
    </div>
  );
}

function UserRow({ u, self, admin, open, onToggle, onChanged }: { u: AdminUser; self: boolean; admin: boolean; open: boolean; onToggle: () => void; onChanged: () => void }) {
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);
  const [cidrs, setCidrs] = useState(u.allowed_cidrs.join("\n"));
  const [issued, setIssued] = useState<MfaEnrollmentCode | null>(null);
  const locked = u.locked_until && new Date(u.locked_until).getTime() > Date.now();

  async function act(fn: () => Promise<unknown>, done?: string) {
    setBusy(true);
    setError(null);
    setMsg(null);
    try {
      await fn();
      if (done) setMsg(done);
      onChanged();
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <tr className={open ? "sel" : undefined}>
        <td>
          <b>{u.username}</b> {self && <Pill tone="accent">you</Pill>}
          <div className="muted tiny">since {time(u.created_at)}</div>
        </td>
        <td>{u.role}</td>
        <td>{u.clearance}</td>
        <td>
          <Pill tone={u.is_active ? "ok" : "crit"}>{u.is_active ? "active" : "disabled"}</Pill> {locked && <Pill tone="warn">locked until {time(u.locked_until)}</Pill>}
        </td>
        <td>{u.mfa_enabled ? <Pill tone="ok">on</Pill> : <span className="muted">off</span>}</td>
        <td className="num">{u.active_sessions}</td>
        <td className="small mono">{u.allowed_cidrs.length ? u.allowed_cidrs.join(", ") : <span className="muted">any network</span>}</td>
        {admin && (
          <td>
            <button className="btn small" onClick={onToggle} aria-expanded={open}>
              {open ? "Close" : "Manage"}
            </button>
          </td>
        )}
      </tr>
      {admin && open && (
        <tr className="editor-row">
          <td colSpan={8}>
            <div className="user-editor">
              <label className="inline-field">
                <span>Role</span>
                <select disabled={busy || self} value={u.role} onChange={(e) => void act(() => api.put(`/api/admin/users/${u.id}/role`, { role: e.target.value as Role }), "Role updated.")}>
                  {(["user", "auditor", "admin"] as Role[]).map((r) => (
                    <option key={r}>{r}</option>
                  ))}
                </select>
              </label>
              <label className="inline-field">
                <span>Clearance</span>
                <select disabled={busy} value={u.clearance} onChange={(e) => void act(() => api.put(`/api/admin/users/${u.id}/clearance`, { clearance: e.target.value as Classification }), "Clearance updated.")}>
                  {CLASSIFICATIONS.map((c) => (
                    <option key={c}>{c}</option>
                  ))}
                </select>
              </label>
              {u.is_active ? (
                <button className="btn danger small" disabled={busy || self} onClick={() => void act(() => api.post(`/api/admin/users/${u.id}/disable`), "Disabled; all sessions revoked.")}>
                  Disable account
                </button>
              ) : (
                <button className="btn small" disabled={busy} onClick={() => void act(() => api.post(`/api/admin/users/${u.id}/enable`), "Enabled.")}>
                  Enable account
                </button>
              )}
              <button
                className="btn small"
                disabled={busy}
                onClick={() => void act(async () => { const r = await api.post<{ sessions_revoked: number }>(`/api/admin/users/${u.id}/revoke-sessions`); setMsg(`${r.sessions_revoked} session(s) revoked.`); })}
              >
                Revoke all sessions
              </button>
              <button
                className="btn small"
                disabled={busy || self || u.mfa_enabled}
                title={u.mfa_enabled ? "The user already has a factor; reset it first if the device is lost." : "Single-use code (24 h) that lets the user enrol an authenticator outside the self-enrolment window."}
                onClick={() =>
                  void act(async () => {
                    setIssued(null);
                    setIssued(await api.post<MfaEnrollmentCode>(`/api/admin/users/${u.id}/mfa-enrollment-code`));
                  })
                }
              >
                Issue MFA enrolment code
              </button>
              <button
                className="btn danger small"
                disabled={busy || self}
                onClick={() =>
                  void act(async () => {
                    if (!window.confirm(`Remove ${u.username}'s second factor and sign out all their sessions? They will need an enrolment code to set up MFA again.`)) return;
                    const r = await api.post<{ sessions_revoked: number }>(`/api/admin/users/${u.id}/mfa-reset`);
                    setIssued(null);
                    setMsg(`MFA reset; ${r.sessions_revoked} session(s) revoked. Issue an enrolment code so the user can enrol again.`);
                  })
                }
              >
                Reset MFA
              </button>
              <form
                className="cidr-form"
                onSubmit={(e) => {
                  e.preventDefault();
                  const list = cidrs.split(/[\s,]+/).map((s) => s.trim()).filter(Boolean);
                  void act(() => api.put(`/api/admin/users/${u.id}/allowed-cidrs`, { cidrs: list }), "Allow list saved.");
                }}
              >
                <label className="field">
                  <span>Allowed networks (CIDR, one per line; empty = any)</span>
                  <textarea rows={3} className="mono" value={cidrs} onChange={(e) => setCidrs(e.target.value)} placeholder="e.g. 10.0.0.0/8" />
                </label>
                <button className="btn small" disabled={busy}>
                  Save allow list
                </button>
              </form>
            </div>
            {issued && (
              <div className="notice notice-warn compact">
                Enrolment code for <b>{u.username}</b>: <code className="secret">{issued.enrollment_code}</code>{" "}
                <CopyButton text={issued.enrollment_code} /> Single use, expires {time(issued.expires_at)}. It is shown only
                now (the server stores only a keyed hash). Give it to the user over a channel you trust, not the one a password
                thief could read.
                <button className="btn ghost small" onClick={() => setIssued(null)}>
                  Hide
                </button>
              </div>
            )}
            {self && <p className="hint">You cannot change your own role, disable yourself, or issue codes / reset MFA for your own account.</p>}
            {msg && <div className="notice notice-ok compact">{msg}</div>}
            <ErrorNotice error={error} compact />
          </td>
        </tr>
      )}
    </>
  );
}

function KmsPanel({ keys, admin }: { keys: ApiState<{ keys: KmsKey[] }>; admin: boolean }) {
  const [purpose, setPurpose] = useState<string>(ROTATABLE[0]);
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<{ purpose: string; key_id: string; version: number; files_rewrapped: number; rewrap_failures: number } | null>(null);
  return (
    <Panel title="KMS keys (metadata only)">
      <ErrorNotice error={keys.error} />
      {keys.data && keys.data.keys.length === 0 && <Empty />}
      {keys.data && keys.data.keys.length > 0 && (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Purpose</th>
                <th>Key ID</th>
                <th className="num">Version</th>
                <th>Algorithm</th>
                <th>State</th>
                <th>Created</th>
              </tr>
            </thead>
            <tbody>
              {keys.data.keys.map((k) => (
                <tr key={`${k.key_id}/${k.version}`}>
                  <td>
                    <code>{k.purpose}</code>
                  </td>
                  <td>
                    <Hash value={k.key_id} n={14} />
                  </td>
                  <td className="num">{k.version}</td>
                  <td className="small">{k.algorithm}</td>
                  <td>
                    <Pill tone={statusTone(k.state)}>{k.state}</Pill>
                  </td>
                  <td className="nowrap">{time(k.created_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {admin && (
        <form
          className="row wrap rotate"
          onSubmit={async (e) => {
            e.preventDefault();
            if (!window.confirm(`Rotate the ${purpose} key?`)) return;
            setBusy(true);
            setError(null);
            setResult(null);
            try {
              setResult(await api.post("/api/admin/kms/rotate", { purpose }));
              await keys.reload();
            } catch (err) {
              setError(err);
            } finally {
              setBusy(false);
            }
          }}
        >
          <label className="inline-field">
            <span>Rotate key</span>
            <select value={purpose} onChange={(e) => setPurpose(e.target.value)}>
              {ROTATABLE.map((p) => (
                <option key={p}>{p}</option>
              ))}
            </select>
          </label>
          <button className="btn danger" disabled={busy}>
            {busy ? "Rotating…" : "Rotate"}
          </button>
          <span className="muted small">
            file-dek-wrap re-wraps every file key; lookup-hmac signs everyone out at next refresh. The audit-pseudonym key is
            not rotatable here (offline, two-person operation, ADR-0007).
          </span>
        </form>
      )}
      {result && (
        <div className={`notice ${result.rewrap_failures ? "notice-warn" : "notice-ok"}`}>
          Rotated {result.purpose} to version {result.version}. Files re-wrapped: {result.files_rewrapped}, failures: {result.rewrap_failures}.
        </div>
      )}
      <ErrorNotice error={error} compact />
    </Panel>
  );
}
