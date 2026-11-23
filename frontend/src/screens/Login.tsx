import { useState } from "react";
import { api, ApiError } from "../api/client";
import type { RegisterAccepted } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { ErrorNotice } from "../components/ui";
import { Mark } from "../components/Mark";

export function Login() {
  const { login, endedReason } = useAuth();
  const [mode, setMode] = useState<"login" | "register">("login");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [password2, setPassword2] = useState("");
  const [totp, setTotp] = useState("");
  const [needTotp, setNeedTotp] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [info, setInfo] = useState<string | null>(null);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setInfo(null);
    if (mode === "register" && password !== password2) {
      setError(new Error("The two passwords differ."));
      return;
    }
    setBusy(true);
    try {
      if (mode === "register") {
        // 202 {"status":"accepted"} whether or not the name was free (the server
        // does not reveal which usernames exist, finding F3).
        await api.post<RegisterAccepted>("/api/auth/register", { username, password }, { anonymous: true });
        setMode("login");
        setPassword("");
        setPassword2("");
        setInfo(
          "If the username is available your account was created — sign in. New accounts must set up an " +
            "authenticator app (MFA) within 24 hours of registration; after that an administrator has to issue an enrolment code.",
        );
      } else {
        await login(username, password, needTotp ? totp : undefined);
      }
    } catch (err) {
      if (err instanceof ApiError && err.status === 401 && err.reasons.includes("mfa-required")) {
        setNeedTotp(true);
        setInfo("Password accepted. This account has MFA: enter your authenticator code.");
      } else if (err instanceof ApiError && err.status === 403 && err.reasons.includes("registration-disabled")) {
        setError(new Error("Self-registration is disabled on this deployment. Ask an administrator for an account."));
      } else {
        if (err instanceof ApiError && err.reasons.includes("mfa-invalid")) setTotp("");
        setError(err);
      }
    } finally {
      setBusy(false);
    }
  }

  const loginHint =
    error instanceof ApiError && error.status === 401 && error.reasons.length === 0
      ? "Sign-in refused. Wrong credentials, a locked account (after repeated failures) and a disabled account all look the same here, by design."
      : error instanceof ApiError && error.status === 429
        ? "Too many attempts from this address. Wait before trying again."
        : null;

  return (
    <div className="login-wrap">
      <div className="login-card">
        <div className="login-brand">
          <Mark size={34} />
          <div>
            <div className="brand-name">ZT Chunked Storage</div>
            <div className="muted small">Zero-trust multi-cloud console</div>
          </div>
        </div>
        <div className="tabs" role="tablist">
          <button role="tab" aria-selected={mode === "login"} className={mode === "login" ? "on" : ""} onClick={() => { setMode("login"); setError(null); }}>
            Sign in
          </button>
          <button role="tab" aria-selected={mode === "register"} className={mode === "register" ? "on" : ""} onClick={() => { setMode("register"); setError(null); setNeedTotp(false); }}>
            Create account
          </button>
        </div>
        {endedReason && mode === "login" && !info && <div className="notice notice-info">{endedReason}</div>}
        <form className="stack" onSubmit={submit}>
          <label className="field">
            <span>Username</span>
            <input
              name="username"
              autoComplete="username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              pattern="[A-Za-z0-9_.\-]{3,64}"
              title="3–64 characters: letters, digits, _ . -"
              required
            />
          </label>
          <label className="field">
            <span>Password</span>
            <input
              name="password"
              type="password"
              autoComplete={mode === "login" ? "current-password" : "new-password"}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              maxLength={256}
              required
            />
          </label>
          {mode === "register" && (
            <>
              <label className="field">
                <span>Repeat password</span>
                <input name="password2" type="password" autoComplete="new-password" value={password2} onChange={(e) => setPassword2(e.target.value)} maxLength={256} required />
              </label>
              <p className="hint">
                At least 12 characters (server default), not a common password, and not containing your username. The server
                enforces the policy; this is only a hint.
              </p>
            </>
          )}
          {mode === "login" && needTotp && (
            <label className="field">
              <span>Authenticator code</span>
              <input
                name="totp"
                className="otp"
                inputMode="numeric"
                autoComplete="one-time-code"
                maxLength={6}
                value={totp}
                onChange={(e) => setTotp(e.target.value.replace(/\D/g, ""))}
                autoFocus
                required
              />
            </label>
          )}
          {info && <div className="notice notice-info">{info}</div>}
          {loginHint && <p className="hint">{loginHint}</p>}
          <ErrorNotice error={error} compact />
          <button className="btn primary block" disabled={busy}>
            {busy ? "Working…" : mode === "login" ? "Sign in" : "Create account"}
          </button>
        </form>
        <p className="muted small login-foot">
          Access tokens stay in memory for 5 minutes and are renewed through an HttpOnly cookie. Every request is
          re-authorised by the server.
        </p>
      </div>
    </div>
  );
}
