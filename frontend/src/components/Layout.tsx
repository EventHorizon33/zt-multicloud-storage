import { useEffect, useState } from "react";
import { NavLink, Outlet } from "react-router-dom";
import { useAuth } from "../auth/AuthContext";
import { Mark } from "./Mark";
import { Pill } from "./ui";

type Theme = "light" | "dark" | "system";

function useTheme(): [Theme, (t: Theme) => void] {
  // Only the colour preference is persisted; no auth material is ever written to storage.
  const [theme, setTheme] = useState<Theme>(() => (localStorage.getItem("zt-theme") as Theme) || "system");
  useEffect(() => {
    localStorage.setItem("zt-theme", theme);
    const root = document.documentElement;
    if (theme === "system") root.removeAttribute("data-theme");
    else root.setAttribute("data-theme", theme);
  }, [theme]);
  return [theme, setTheme];
}

export function Layout() {
  const { me, logout, can } = useAuth();
  const [theme, setTheme] = useTheme();
  if (!me) return null;
  const nav: { to: string; label: string; show: boolean }[] = [
    { to: "/", label: "Dashboard", show: true },
    { to: "/files", label: "Files", show: true },
    { to: "/distribution", label: "Storage distribution", show: true },
    { to: "/security", label: "Security centre", show: true },
    { to: "/audit", label: "Audit explorer", show: true },
    { to: "/account", label: "Account", show: true },
    { to: "/admin", label: can("admin") ? "Administration" : "Keys", show: can("admin", "auditor") },
  ];
  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="brand">
          <Mark size={26} />
          <div>
            <div className="brand-name">ZT Chunked Storage</div>
            <div className="muted tiny">Providers hold ciphertext only</div>
          </div>
        </div>
        <nav aria-label="Main">
          {nav
            .filter((n) => n.show)
            .map((n) => (
              <NavLink key={n.to} to={n.to} end={n.to === "/"} className={({ isActive }) => (isActive ? "nav on" : "nav")}>
                {n.label}
              </NavLink>
            ))}
        </nav>
        <div className="side-foot">
          <div className="who">
            <div className="who-name">{me.user.username}</div>
            <div className="who-meta">
              <Pill tone={me.user.role === "admin" ? "accent" : me.user.role === "auditor" ? "info" : "neutral"}>{me.user.role}</Pill>
              <Pill tone="neutral" title="Clearance: highest classification you may read or create">
                {me.user.clearance}
              </Pill>
            </div>
            <div className="who-mfa small">
              {me.user.mfa_enabled ? (
                me.mfa_fresh ? (
                  <span className="ok-text">MFA verified recently</span>
                ) : me.restricted ? (
                  <span className="warn-text">MFA enrolled; sign in again with a code</span>
                ) : (
                  <span className="muted">MFA enrolled, step-up needed for sensitive actions</span>
                )
              ) : (
                <span className="warn-text">No MFA enrolled</span>
              )}
            </div>
          </div>
          <div className="row">
            <label className="sr-only" htmlFor="theme">
              Theme
            </label>
            <select id="theme" className="small-select" value={theme} onChange={(e) => setTheme(e.target.value as Theme)}>
              <option value="system">System theme</option>
              <option value="light">Light</option>
              <option value="dark">Dark</option>
            </select>
            <button className="btn small ghost" onClick={() => void logout()}>
              Sign out
            </button>
          </div>
        </div>
      </aside>
      <main className="main">
        {me.restricted && (
          <div className="notice notice-warn banner">
            This session is restricted: policy requires MFA at sign-in. Enrol an authenticator under Account, then sign
            in again with a code (activating a factor does not upgrade this session); other actions return{" "}
            <code>mfa-enrollment-required</code> until then.
          </div>
        )}
        <Outlet />
      </main>
    </div>
  );
}
