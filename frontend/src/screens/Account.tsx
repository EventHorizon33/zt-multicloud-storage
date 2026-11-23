import { useEffect, useState } from "react";
import QRCode from "qrcode";
import { api, ApiError } from "../api/client";
import type { Me, Session } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { Empty, ErrorNotice, Hash, KV, PageHead, Panel, Pill } from "../components/ui";
import { ago, time } from "../lib/format";
import { useApi } from "../lib/useApi";

export function Account() {
  const { me } = useAuth();
  if (!me) return null;
  return (
    <div className="page">
      <PageHead title="Account" />
      <div className="grid-2">
        <Panel title="Profile">
          <KV
            rows={[
              ["Username", me.user.username],
              ["User ID", <Hash value={me.user.id} n={12} />],
              ["Role", me.user.role],
              ["Clearance", me.user.clearance],
              ["Created", time(me.user.created_at)],
              ["Audit pseudonym", <Hash value={me.audit_pseudonym} n={14} />],
              ["This session", <span>started {ago(me.session.created_at)}, expires {time(me.session.expires_at)}</span>],
              ["Second factor", me.user.mfa_enabled ? (me.mfa_fresh ? <Pill tone="ok">verified recently</Pill> : <Pill tone="info">enrolled</Pill>) : <Pill tone="warn">not enrolled</Pill>],
            ]}
          />
          <p className="muted small">Your audit pseudonym is how your actions appear in the audit log. Filter on it in the Audit explorer.</p>
        </Panel>
        <MfaPanel me={me} />
      </div>
      <Sessions me={me} />
      <PasswordPanel me={me} />
    </div>
  );
}

function MfaPanel({ me }: { me: Me }) {
  const { reloadMe, logout } = useAuth();
  const [enrol, setEnrol] = useState<{ secret: string; otpauth_uri: string } | null>(null);
  // ADR-0010: outside the 24 h self-enrolment window the server answers 403
  // mfa-enrollment-requires-approval and an admin-issued enrolment code is needed.
  const [needCode, setNeedCode] = useState(false);
  const [enrolCode, setEnrolCode] = useState("");
  const [activated, setActivated] = useState(false);
  const [qr, setQr] = useState<string | null>(null);
  const [code, setCode] = useState("");
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);

  useEffect(() => {
    if (!enrol) {
      setQr(null);
      return;
    }
    // Rendered locally to an SVG data URL: the secret never leaves the browser.
    QRCode.toString(enrol.otpauth_uri, { type: "svg", margin: 1, errorCorrectionLevel: "M" })
      .then((svg) => setQr(`data:image/svg+xml;charset=utf-8,${encodeURIComponent(svg)}`))
      .catch(() => setQr(null));
  }, [enrol]);

  async function act(fn: () => Promise<void>) {
    setBusy(true);
    setError(null);
    setMsg(null);
    try {
      await fn();
    } catch (e) {
      if (e instanceof ApiError && e.status === 403 && e.reasons.includes("mfa-enrollment-requires-approval")) {
        setNeedCode(true);
        setError(null);
      } else if (e instanceof ApiError && e.status === 403 && e.reasons.includes("mfa-enrollment-code-invalid")) {
        setEnrolCode("");
        setError(new Error("That enrolment code is not valid: wrong, expired, already used, or issued for another account."));
      } else {
        setError(e);
      }
      setCode("");
    } finally {
      setBusy(false);
    }
  }

  const codeInput = (
    <label className="field">
      <span>Authenticator code</span>
      <input className="otp" inputMode="numeric" autoComplete="one-time-code" maxLength={6} value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))} />
    </label>
  );

  return (
    <Panel title="Two-factor authentication (TOTP)">
      {activated ? (
        <>
          <p>
            Your authenticator is set up, but <b>this session is still password-only</b>: activating a factor never upgrades the
            session it was started from. Sign in again with your password and an authenticator code to get an MFA-verified session.
          </p>
          <button className="btn primary" onClick={() => void logout()}>
            Sign out and sign in again
          </button>
        </>
      ) : me.user.mfa_enabled ? (
        <>
          <p>
            MFA is on. Sensitive actions (delete, share, policy and key changes, confidential downloads) ask for a code when your last check
            is too old.
          </p>
          <form
            className="stack"
            onSubmit={(e) => {
              e.preventDefault();
              void act(async () => {
                await api.post<Me>("/api/auth/mfa/verify", { code }, { noStepUp: true });
                setCode("");
                setMsg("Verified. Step-up actions are allowed for the configured window.");
                await reloadMe();
              });
            }}
          >
            {codeInput}
            <div className="row">
              <button className="btn primary" disabled={busy || code.length !== 6}>
                Verify now
              </button>
              <button
                type="button"
                className="btn danger"
                disabled={busy || code.length !== 6}
                onClick={() =>
                  void act(async () => {
                    if (!window.confirm("Turn off MFA for this account?")) return;
                    await api.post<Me>("/api/auth/mfa/disable", { code }, { noStepUp: true });
                    setCode("");
                    setMsg("MFA disabled.");
                    await reloadMe();
                  })
                }
              >
                Disable MFA
              </button>
            </div>
          </form>
        </>
      ) : !enrol ? (
        needCode ? (
          <form
            className="stack"
            onSubmit={(e) => {
              e.preventDefault();
              void act(async () => {
                setEnrol(await api.post("/api/auth/mfa/enroll", { enrollment_code: enrolCode.trim() }, { noStepUp: true }));
                setNeedCode(false);
                setEnrolCode("");
              });
            }}
          >
            <div className="notice notice-warn">
              This account is older than the self-enrolment window (24 hours after registration), or it had a second factor
              before. To protect against someone who only knows your password, adding a factor now needs a one-time enrolment
              code from an administrator. Ask them to issue one, then enter it here.
            </div>
            <label className="field">
              <span>Admin enrolment code</span>
              <input
                name="enrollment_code"
                className="mono"
                autoComplete="off"
                placeholder="XXXX-XXXX-XXXX-XXXX"
                maxLength={32}
                value={enrolCode}
                onChange={(e) => setEnrolCode(e.target.value.toUpperCase())}
              />
            </label>
            <div className="row">
              <button className="btn primary" disabled={busy || enrolCode.replace(/[\s-]/g, "").length !== 16}>
                Start enrolment with code
              </button>
              <button type="button" className="btn ghost" onClick={() => { setNeedCode(false); setEnrolCode(""); }}>
                Cancel
              </button>
            </div>
          </form>
        ) : (
          <>
            <p>Add an authenticator app. Without it you cannot delete or share files, or open confidential downloads.</p>
            <button className="btn primary" disabled={busy} onClick={() => void act(async () => setEnrol(await api.post("/api/auth/mfa/enroll", undefined, { noStepUp: true })))}>
              Start enrolment
            </button>
          </>
        )
      ) : (
        <form
          className="stack"
          onSubmit={(e) => {
            e.preventDefault();
            void act(async () => {
              await api.post<Me>("/api/auth/mfa/activate", { code }, { noStepUp: true });
              setEnrol(null);
              setCode("");
              setActivated(true);
              await reloadMe();
            });
          }}
        >
          <div className="enrol">
            {qr ? <img src={qr} alt="QR code for your authenticator app" width={176} height={176} className="qr" /> : <div className="qr muted">QR unavailable</div>}
            <div className="stack">
              <p className="small">Scan the code, or type the secret into your authenticator. It is shown only once.</p>
              <div>
                <div className="muted tiny">Secret</div>
                <code className="secret">{enrol.secret.replace(/(.{4})/g, "$1 ").trim()}</code>
              </div>
            </div>
          </div>
          {codeInput}
          <div className="row">
            <button className="btn primary" disabled={busy || code.length !== 6}>
              Activate MFA
            </button>
            <button type="button" className="btn ghost" onClick={() => setEnrol(null)}>
              Cancel
            </button>
          </div>
        </form>
      )}
      {msg && <div className="notice notice-ok">{msg}</div>}
      <ErrorNotice error={error} compact />
    </Panel>
  );
}

/** Session management needs an MFA-verified session (the server answers 403 mfa-required to a
 *  password-only or factor-less session), so a restricted session is told so instead of calling. */
function sessionsAllowed(me: Me): boolean {
  return me.user.mfa_enabled && !me.restricted;
}

function Sessions({ me }: { me: Me }) {
  const allowed = sessionsAllowed(me);
  const q = useApi(() => (allowed ? api.get<Session[]>("/api/auth/sessions") : Promise.resolve([] as Session[])), [allowed]);
  const [error, setError] = useState<unknown>(null);
  if (!allowed) {
    return (
      <Panel title="Active sessions">
        <p className="muted small">
          Listing and revoking sessions needs a session verified with your authenticator.{" "}
          {me.user.mfa_enabled ? "Sign in again with your password and an authenticator code." : "Enrol an authenticator above first."}
        </p>
      </Panel>
    );
  }
  return (
    <Panel title="Active sessions">
      <ErrorNotice error={q.error ?? error} compact />
      {q.data && q.data.length === 0 && <Empty />}
      {q.data && q.data.length > 0 && (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Session</th>
                <th>Started</th>
                <th>Last seen</th>
                <th>Expires</th>
                <th>MFA</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {q.data.map((s) => (
                <tr key={s.id}>
                  <td>
                    <Hash value={s.id} n={10} copy={false} /> {s.current && <Pill tone="accent">this browser</Pill>}
                  </td>
                  <td className="nowrap">{time(s.created_at)}</td>
                  <td className="nowrap">{ago(s.last_seen_at)}</td>
                  <td className="nowrap">{time(s.expires_at)}</td>
                  <td>{s.mfa_verified ? <Pill tone="ok">verified</Pill> : <span className="muted">no</span>}</td>
                  <td>
                    {!s.current && (
                      <button
                        className="btn small"
                        onClick={async () => {
                          setError(null);
                          try {
                            await api.del(`/api/auth/sessions/${s.id}`);
                            await q.reload();
                          } catch (e) {
                            setError(e);
                          }
                        }}
                      >
                        Revoke
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Panel>
  );
}

function PasswordPanel({ me }: { me: Me }) {
  const [cur, setCur] = useState("");
  const [next, setNext] = useState("");
  const [next2, setNext2] = useState("");
  const [error, setError] = useState<unknown>(null);
  const [msg, setMsg] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  return (
    <Panel title="Change password">
      <form
        className="form-grid narrow"
        onSubmit={async (e) => {
          e.preventDefault();
          setError(null);
          setMsg(null);
          if (next !== next2) {
            setError(new Error("The two new passwords differ."));
            return;
          }
          setBusy(true);
          try {
            const r = await api.post<{ sessions_revoked: number }>("/api/auth/password", { current_password: cur, new_password: next });
            setMsg(`Password changed. ${r.sessions_revoked} other session(s) signed out.`);
            setCur("");
            setNext("");
            setNext2("");
          } catch (err) {
            setError(err);
          } finally {
            setBusy(false);
          }
        }}
      >
        <label className="field">
          <span>Current password</span>
          <input type="password" autoComplete="current-password" value={cur} onChange={(e) => setCur(e.target.value)} required maxLength={256} />
        </label>
        <label className="field">
          <span>New password</span>
          <input type="password" autoComplete="new-password" value={next} onChange={(e) => setNext(e.target.value)} required maxLength={256} />
        </label>
        <label className="field">
          <span>Repeat new password</span>
          <input type="password" autoComplete="new-password" value={next2} onChange={(e) => setNext2(e.target.value)} required maxLength={256} />
        </label>
        <div className="field end-field">
          <button className="btn primary" disabled={busy || !me.user.mfa_enabled}>
            Change password
          </button>
        </div>
      </form>
      <p className="hint">
        At least 12 characters, not a common password, not containing your username. A password change needs a recent check with your
        authenticator (you will be asked for a code). Other sessions are signed out, except sessions that verified your authenticator
        more recently than this one.
      </p>
      {!me.user.mfa_enabled && <div className="notice notice-warn">Enrol an authenticator first: accounts without a second factor cannot change their password here.</div>}
      {msg && <div className="notice notice-ok">{msg}</div>}
      <ErrorNotice error={error} compact />
    </Panel>
  );
}
