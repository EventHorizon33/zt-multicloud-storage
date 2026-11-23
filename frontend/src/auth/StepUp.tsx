import { useEffect, useRef, useState, type ReactNode } from "react";
import { api, ApiError } from "../api/client";
import type { Me } from "../api/types";
import { ErrorNotice, Modal } from "../components/ui";
import { useAuth } from "./AuthContext";

interface Pending {
  err: ApiError;
  resolve: (ok: boolean) => void;
}

/**
 * Registers the API client's step-up handler. When the server answers 403 with
 * mfa-required / mfa-stale, this dialog asks for a TOTP code, calls
 * POST /api/auth/mfa/verify and tells the client to retry the original request.
 */
export function StepUpProvider({ children }: { children: ReactNode }) {
  const [pending, setPending] = useState<Pending | null>(null);
  const { reloadMe } = useAuth();

  useEffect(() => {
    api.setStepUpHandler(
      (err) =>
        new Promise<boolean>((resolve) => {
          setPending({ err, resolve });
        }),
    );
    return () => api.setStepUpHandler(null);
  }, []);

  return (
    <>
      {children}
      {pending && (
        <StepUpDialog
          err={pending.err}
          onDone={(ok) => {
            pending.resolve(ok);
            setPending(null);
            if (ok) void reloadMe();
          }}
        />
      )}
    </>
  );
}

function StepUpDialog({ err, onDone }: { err: ApiError; onDone: (ok: boolean) => void }) {
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const done = useRef(false);
  const finish = (ok: boolean) => {
    if (done.current) return;
    done.current = true;
    onDone(ok);
  };

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await api.post<Me>("/api/auth/mfa/verify", { code }, { noStepUp: true });
      finish(true);
    } catch (e2) {
      setError(e2);
      setCode("");
    } finally {
      setBusy(false);
    }
  }

  const stale = err.reasons.includes("mfa-stale");
  return (
    <Modal title="Confirm with your authenticator" onClose={() => finish(false)}>
      <form onSubmit={submit} className="stack">
        <p>
          {stale
            ? "Your last second-factor check is older than the policy allows for this action."
            : "This action requires a recent second factor."}{" "}
          Enter the 6-digit code from your authenticator app. The action runs again after the code is accepted.
        </p>
        <p className="muted small">
          Server decision: <code>{err.status} {err.code}</code>, reasons <code>{err.reasons.join(", ") || "none"}</code>
          {err.requestId && (
            <>
              {" "}
              , request <code>{err.requestId}</code>
            </>
          )}
        </p>
        <label className="field">
          <span>Authenticator code</span>
          <input
            inputMode="numeric"
            autoComplete="one-time-code"
            pattern="[0-9]{6}"
            maxLength={6}
            value={code}
            onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))}
            required
            className="otp"
          />
        </label>
        <ErrorNotice error={error} compact />
        <div className="row end">
          <button type="button" className="btn ghost" onClick={() => finish(false)}>
            Cancel
          </button>
          <button className="btn primary" disabled={busy || code.length !== 6}>
            {busy ? "Verifying…" : "Verify and continue"}
          </button>
        </div>
      </form>
    </Modal>
  );
}
