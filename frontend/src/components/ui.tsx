import { useEffect, useId, useRef, useState, type ReactNode } from "react";
import { ApiError } from "../api/client";
import { hashHue, short } from "../lib/format";

/** Human hint for well-known server reason codes. The code itself is always shown too. */
const REASON_HINTS: Record<string, string> = {
  "mfa-required": "This action needs a recent second factor.",
  "mfa-stale": "Your last MFA check is too old for this action.",
  "enroll-mfa": "Enrol an authenticator under Account first.",
  "mfa-enrollment-required": "Policy requires MFA for this session. Enrol it under Account.",
  "insufficient-clearance": "The file's classification is above your clearance.",
  "admin-no-content-access": "Administrators cannot read other users' file content.",
  "download-rate-exceeded": "Download volume limit reached; you are temporarily blocked.",
  "network-not-allowed": "Your network is not on this account's allow list.",
  "default-deny": "No policy rule allows this.",
  "not-owner": "Only the owner can do this.",
  "file-busy": "Another operation on this file is running. Try again shortly.",
  "file-not-available": "Only committed files support this.",
  "data-unavailable": "A chunk has no reachable replica right now.",
  "storage-unavailable": "Not enough storage providers accepted the data.",
  "share-target-invalid": "That user cannot receive shares (unknown, disabled or yourself).",
  "password-too-short": "Password is shorter than the policy minimum.",
  "password-too-common": "Password is on the common-password list.",
  "password-contains-username": "Password must not contain the username.",
  "password-unchanged": "The new password equals the current one.",
  "current-password-invalid": "Current password is wrong.",
  "mfa-enrollment-requires-approval": "Adding a factor to this account needs an enrolment code from an administrator.",
  "mfa-enrollment-code-invalid": "The enrolment code is wrong, expired, already used or for another account.",
  "mfa-enrollment-expired": "The enrolment took too long. Start it again.",
  "mfa-already-enabled": "A factor is already active; replacing it needs a code from the current one.",
  "registration-disabled": "Self-registration is disabled. Ask an administrator for an account.",
  "mfa-invalid": "The code was not accepted.",
  "cannot-modify-self": "You cannot change your own account here.",
  "last-admin": "At least one active admin must remain.",
  "pseudonym-key-rotation-disabled": "The audit-pseudonym key is rotated only offline by two operators (ADR-0007).",
  "bad-forwarded-for": "The proxy sent an unusable X-Forwarded-For header.",
  "bad-multipart": "The upload body is not valid multipart/form-data.",
  "multipart-limit-exceeded": "A part header of the upload is too large.",
  "step-up-mfa": "Confirm with your authenticator to continue.",
  "rate-limited": "Too many requests; wait and try again.",
};

export function ErrorNotice({ error, onRetry, compact }: { error: unknown; onRetry?: () => void; compact?: boolean }) {
  if (!error) return null;
  if (error instanceof ApiError) {
    const items = [...error.reasons, ...error.obligations.filter((o) => !error.reasons.includes(o))];
    return (
      <div className={`notice notice-err${compact ? " compact" : ""}`} role="alert">
        <div className="notice-head">
          <strong>
            {error.status} {error.code}
          </strong>
          {error.retryAfter !== null && <span>retry in {error.retryAfter} s</span>}
          {error.requestId && (
            <span className="reqid">
              request <code>{error.requestId}</code> <CopyButton text={error.requestId} />
            </span>
          )}
        </div>
        {items.length > 0 && (
          <ul className="reasons">
            {items.map((r) => (
              <li key={r}>
                <code>{r}</code>
                {REASON_HINTS[r] && <span> {REASON_HINTS[r]}</span>}
              </li>
            ))}
          </ul>
        )}
        {onRetry && (
          <button className="btn small" onClick={onRetry}>
            Try again
          </button>
        )}
      </div>
    );
  }
  const msg = error instanceof Error ? error.message : String(error);
  return (
    <div className="notice notice-err" role="alert">
      <div className="notice-head">
        <strong>Request failed</strong> <span>{msg === "network error" || msg.includes("fetch") ? "The API is unreachable." : msg}</span>
      </div>
      {onRetry && (
        <button className="btn small" onClick={onRetry}>
          Try again
        </button>
      )}
    </div>
  );
}

export function Empty({ children = "No data yet" }: { children?: ReactNode }) {
  return <div className="empty">{children}</div>;
}

export function CopyButton({ text, label = "Copy" }: { text: string; label?: string }) {
  const [done, setDone] = useState(false);
  return (
    <button
      type="button"
      className="copy"
      title={`Copy ${text}`}
      aria-label={`${label}: ${text}`}
      onClick={async (e) => {
        e.stopPropagation();
        try {
          await navigator.clipboard.writeText(text);
          setDone(true);
          window.setTimeout(() => setDone(false), 1200);
        } catch {
          /* clipboard unavailable (insecure context) */
        }
      }}
    >
      {done ? "Copied" : label}
    </button>
  );
}

/** A truncated identifier with copy. `swatch` adds the hash-derived colour chip used for chain continuity. */
export function Hash({ value, n = 10, swatch = false, copy = true }: { value: string | null | undefined; n?: number; swatch?: boolean; copy?: boolean }) {
  if (!value) return <span className="muted">–</span>;
  return (
    <span className="hash" title={value}>
      {swatch && <span className="swatch" style={{ ["--h" as string]: hashHue(value) }} aria-hidden />}
      <code>{short(value, n)}</code>
      {copy && <CopyButton text={value} />}
    </span>
  );
}

export type Tone = "ok" | "warn" | "crit" | "info" | "neutral" | "accent";

export function Pill({ tone = "neutral", children, title }: { tone?: Tone; children: ReactNode; title?: string }) {
  return (
    <span className={`pill pill-${tone}`} title={title}>
      {children}
    </span>
  );
}

export function outcomeTone(o: string): Tone {
  return o === "success" ? "ok" : o === "denied" ? "warn" : o === "failure" || o === "error" ? "crit" : "neutral";
}
export function severityTone(s: string): Tone {
  return s === "critical" ? "crit" : s === "warning" ? "warn" : "info";
}
export function statusTone(s: string): Tone {
  switch (s) {
    case "committed":
    case "stored":
    case "ok":
    case "closed":
    case "active":
      return "ok";
    case "pending":
    case "uploading":
    case "deleting":
    case "half-open":
    case "missing":
    case "decrypt-only":
    case "unavailable":
      return "warn";
    case "failed":
    case "corrupt":
    case "open":
      return "crit";
    default:
      return "neutral";
  }
}

export function Panel({ title, actions, children, className = "" }: { title?: ReactNode; actions?: ReactNode; children: ReactNode; className?: string }) {
  return (
    <section className={`panel ${className}`}>
      {(title || actions) && (
        <header className="panel-head">
          {title && <h2>{title}</h2>}
          {actions && <div className="panel-actions">{actions}</div>}
        </header>
      )}
      {children}
    </section>
  );
}

export function PageHead({ title, sub, children }: { title: string; sub?: ReactNode; children?: ReactNode }) {
  return (
    <div className="page-head">
      <div>
        <h1>{title}</h1>
        {sub && <p className="sub">{sub}</p>}
      </div>
      {children && <div className="page-actions">{children}</div>}
    </div>
  );
}

export function Modal({ title, onClose, children, wide }: { title: string; onClose: () => void; children: ReactNode; wide?: boolean }) {
  const ref = useRef<HTMLDivElement>(null);
  const id = useId();
  useEffect(() => {
    const prev = document.activeElement as HTMLElement | null;
    const first = ref.current?.querySelector<HTMLElement>("input, select, textarea, button");
    first?.focus();
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => {
      window.removeEventListener("keydown", onKey);
      prev?.focus?.();
    };
  }, [onClose]);
  return (
    <div className="scrim" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div className={`modal${wide ? " wide" : ""}`} role="dialog" aria-modal="true" aria-labelledby={id} ref={ref}>
        <header className="modal-head">
          <h2 id={id}>{title}</h2>
          <button className="icon-btn" onClick={onClose} aria-label="Close">
            ×
          </button>
        </header>
        <div className="modal-body">{children}</div>
      </div>
    </div>
  );
}

export function Drawer({ title, onClose, children }: { title: ReactNode; onClose: () => void; children: ReactNode }) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);
  return (
    <aside className="drawer" role="complementary">
      <header className="modal-head">
        <h2>{title}</h2>
        <button className="icon-btn" onClick={onClose} aria-label="Close details">
          ×
        </button>
      </header>
      <div className="drawer-body">{children}</div>
    </aside>
  );
}

/** Horizontal bars. Values are drawn proportionally to the largest one; labels and numbers stay as text. */
export function Bars({
  rows,
  format = (n) => String(n),
}: {
  rows: { label: ReactNode; value: number; tone?: string; detail?: ReactNode; key: string }[];
  format?: (n: number) => string;
}) {
  const max = Math.max(0, ...rows.map((r) => r.value));
  if (rows.length === 0) return <Empty />;
  return (
    <div className="bars">
      {rows.map((r) => (
        <div className="bar-row" key={r.key}>
          <div className="bar-label">{r.label}</div>
          <div className="bar-track" aria-hidden>
            <div className="bar-fill" style={{ width: max > 0 ? `${(r.value / max) * 100}%` : "0%", background: r.tone }} />
          </div>
          <div className="bar-value">
            {format(r.value)}
            {r.detail && <span className="muted"> {r.detail}</span>}
          </div>
        </div>
      ))}
    </div>
  );
}

const PROVIDER_COLORS: Record<string, string> = {
  "aws-s3": "var(--p-aws)",
  "azure-blob": "var(--p-azure)",
  gcs: "var(--p-gcs)",
};
export function providerColor(p: string): string {
  return PROVIDER_COLORS[p] ?? "var(--accent)";
}

export function ProviderName({ name }: { name: string }) {
  return (
    <span className="provider">
      <span className="pdot" style={{ background: providerColor(name) }} aria-hidden />
      {name}
    </span>
  );
}

export function KV({ rows }: { rows: [ReactNode, ReactNode][] }) {
  return (
    <dl className="kv">
      {rows.map(([k, v], i) => (
        <div key={i}>
          <dt>{k}</dt>
          <dd>{v}</dd>
        </div>
      ))}
    </dl>
  );
}

export function Updated({ at, loading }: { at: number | null; loading: boolean }) {
  const [, tick] = useState(0);
  useEffect(() => {
    const t = window.setInterval(() => tick((x) => x + 1), 1000);
    return () => window.clearInterval(t);
  }, []);
  if (!at) return <span className="muted small">{loading ? "Loading…" : ""}</span>;
  const s = Math.round((Date.now() - at) / 1000);
  return (
    <span className="muted small live">
      <span className={`live-dot${loading ? " busy" : ""}`} aria-hidden /> updated {s < 2 ? "now" : `${s} s ago`}
    </span>
  );
}
