import { useState } from "react";
import { useSearchParams } from "react-router-dom";
import { api } from "../api/client";
import {
  FAULT_MODES,
  type AdminFileList,
  type FaultMode,
  type FaultStatus,
  type FileDistribution,
  type FileList,
  type FileRow,
  type ProviderHealth,
  type ProvidersResponse,
  type StorageDistribution,
  type StorageMetrics,
} from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { Bars, Empty, ErrorNotice, Hash, PageHead, Panel, Pill, ProviderName, Updated, providerColor, statusTone } from "../components/ui";
import { ago, bytes, num, short, time } from "../lib/format";
import { useApi } from "../lib/useApi";

export function Distribution() {
  const { can } = useAuth();
  const isAdmin = can("admin");
  const providers = useApi(() => api.get<ProvidersResponse>("/api/storage/providers"), [], 10_000);
  const agg = useApi(() => api.get<StorageDistribution>("/api/storage/distribution"), [], 10_000);
  const metrics = useApi(() => api.get<StorageMetrics>("/api/storage/metrics"), [], 10_000);
  const own = useApi(() => api.get<FileList>("/api/files"), []);
  const all = useApi(isAdmin ? () => api.get<AdminFileList>("/api/admin/files", { limit: 200 }) : null, [isAdmin]);
  const [params, setParams] = useSearchParams();
  const fileId = params.get("file");

  const providerNames = providers.data?.providers.map((p) => p.provider) ?? [];
  const choices: FileRow[] = [...(own.data?.files ?? [])];
  for (const f of all.data?.files ?? []) if (!choices.some((c) => c.id === f.id)) choices.push(f);
  const committed = choices.filter((f) => f.status === "committed");
  const effectiveId = fileId ?? committed[0]?.id ?? null;

  return (
    <div className="page">
      <PageHead
        title="Storage distribution"
        sub={
          providers.data
            ? `Each chunk is written to ${providers.data.replication_factor} providers (a write needs at least ${providers.data.min_write_replicas}). Providers only ever receive ciphertext.`
            : undefined
        }
      >
        <Updated at={providers.updatedAt} loading={providers.loading} />
      </PageHead>

      <Panel title="Provider health">
        <ErrorNotice error={providers.error} onRetry={() => void providers.reload()} />
        {providers.data && <HealthCards providers={providers.data.providers} />}
      </Panel>

      <Panel
        title="Chunk map"
        actions={
          choices.length > 0 && (
            <select aria-label="File" value={effectiveId ?? ""} onChange={(e) => setParams({ file: e.target.value }, { replace: true })}>
              {choices.map((f) => (
                <option key={f.id} value={f.id}>
                  {f.filename ?? `file ${short(f.id, 8)}${f.owner_username ? ` (${f.owner_username})` : ""}`} [{f.status}]
                </option>
              ))}
            </select>
          )
        }
      >
        <ErrorNotice error={own.error} />
        {own.data && choices.length === 0 && <Empty>No files yet. Upload one under Files to see its chunks spread across providers.</Empty>}
        {effectiveId && <ChunkGrid key={effectiveId} fileId={effectiveId} providerNames={providerNames} />}
        {isAdmin && all.data && <p className="muted small">As an administrator you can see the placement of every file ({all.data.total}); names stay hidden.</p>}
      </Panel>

      <div className="grid-2">
        <Panel title={agg.data ? `Replicas per provider (${agg.data.scope === "all" ? "all users" : "your files"})` : "Replicas per provider"}>
          <ErrorNotice error={agg.error} />
          {agg.data &&
            (Object.values(agg.data.distribution).every((v) => v.replicas === 0) ? (
              <Empty />
            ) : (
              <>
                <Bars
                  format={(n) => `${num(n)} replica${n === 1 ? "" : "s"}`}
                  rows={Object.entries(agg.data.distribution).map(([p, v]) => ({
                    key: p,
                    label: <ProviderName name={p} />,
                    value: v.replicas,
                    tone: providerColor(p),
                    detail: `(${bytes(v.bytes)})`,
                  }))}
                />
                <table className="table tight">
                  <thead>
                    <tr>
                      <th>Provider</th>
                      {statusKeys(agg.data).map((s) => (
                        <th key={s} className="num">
                          {s}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {Object.entries(agg.data.distribution).map(([p, v]) => (
                      <tr key={p}>
                        <td>
                          <ProviderName name={p} />
                        </td>
                        {statusKeys(agg.data!).map((s) => (
                          <td key={s} className="num">
                            {v.by_status[s] ?? 0}
                          </td>
                        ))}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </>
            ))}
          {agg.data && (
            <p className="muted small">
              {num(agg.data.files)} committed files, {num(agg.data.chunks)} chunks, {bytes(agg.data.bytes)}. Files by status:{" "}
              {Object.entries(agg.data.files_by_status).map(([k, v]) => `${k} ${v}`).join(", ")}.
            </p>
          )}
        </Panel>
        <Panel title="Storage operations and failures" actions={<Updated at={metrics.updatedAt} loading={metrics.loading} />}>
          <ErrorNotice error={metrics.error} />
          {metrics.data && <MetricsTable m={metrics.data} />}
        </Panel>
      </div>

      {isAdmin && providers.data?.fault_injection_enabled && <FaultControls providers={providerNames} onChange={() => void providers.reload()} />}
    </div>
  );
}

function statusKeys(d: StorageDistribution): string[] {
  const s = new Set<string>();
  for (const v of Object.values(d.distribution)) for (const k of Object.keys(v.by_status)) s.add(k);
  return [...s].sort();
}

export function HealthCards({ providers }: { providers: ProviderHealth[] }) {
  if (providers.length === 0) return <Empty />;
  return (
    <div className="hcards">
      {providers.map((p) => (
        <div key={p.provider} className={`hcard${p.healthy === false ? " down" : ""}${p.injected ? " injected" : ""}`} style={{ ["--pc" as string]: providerColor(p.provider) }}>
          <div className="row between">
            <ProviderName name={p.provider} />
            <span className="muted small">{p.kind}</span>
          </div>
          {p.injected && <div className="sim-flag">SIMULATED FAULT: {p.fault_mode}</div>}
          <div className="row wrap">
            <Pill tone={p.healthy === null ? "neutral" : p.healthy ? "ok" : "crit"}>{p.healthy === null ? "not yet checked" : p.healthy ? "healthy" : "unhealthy"}</Pill>
            <Pill tone={statusTone(p.state)}>circuit {p.state}</Pill>
          </div>
          <dl className="hstats">
            <div>
              <dt>Latency</dt>
              <dd>{p.latency_ms !== null ? `${p.latency_ms.toFixed(1)} ms` : "–"}</dd>
            </div>
            <div>
              <dt>Consecutive failures</dt>
              <dd className={p.consecutive_failures > 0 ? "crit-text" : undefined}>{p.consecutive_failures}</dd>
            </div>
            <div>
              <dt>Successes / failures</dt>
              <dd>
                {num(p.total_successes)} / {num(p.total_failures)}
              </dd>
            </div>
            <div>
              <dt>Last check</dt>
              <dd title={p.last_checked ?? undefined}>{ago(p.last_checked)}</dd>
            </div>
          </dl>
          {p.last_error && (
            <div className="small">
              Last error: <code>{p.last_error}</code>
            </div>
          )}
        </div>
      ))}
    </div>
  );
}

function ChunkGrid({ fileId, providerNames }: { fileId: string; providerNames: string[] }) {
  const q = useApi(() => api.get<FileDistribution>(`/api/files/${fileId}/distribution`), [fileId], 15_000);
  const d = q.data;
  if (q.error) return <ErrorNotice error={q.error} onRetry={() => void q.reload()} />;
  if (!d) return <div className="muted">Loading…</div>;
  const cols = [...providerNames];
  for (const c of d.chunks) for (const r of c.replicas) if (!cols.includes(r.provider)) cols.push(r.provider);
  const fullyReplicated = d.chunks.filter((c) => c.replicas.filter((r) => r.status === "stored").length >= d.replication_factor).length;
  return (
    <>
      <div className="row wrap gridmeta">
        <span>
          Status <Pill tone={statusTone(d.status)}>{d.status}</Pill>
        </span>
        <span>
          {d.chunk_count} chunk{d.chunk_count === 1 ? "" : "s"}, replication factor {d.replication_factor}
        </span>
        <span>
          Replication{" "}
          <Pill tone={fullyReplicated === d.chunks.length ? "ok" : "warn"}>
            {fullyReplicated} of {d.chunks.length} chunks fully replicated
          </Pill>
        </span>
        <span className="muted small">
          Stored replicas: {Object.entries(d.providers).map(([p, n]) => `${p} ${n}`).join(", ") || "none"}
        </span>
      </div>
      {d.chunks.length === 0 ? (
        <Empty>This file has no chunks recorded.</Empty>
      ) : (
        <div className="table-wrap">
          <table className="table chunkgrid" aria-label="Chunk replicas by provider">
            <thead>
              <tr>
                <th className="num">Chunk</th>
                <th>Chunk ID</th>
                <th className="num">Ciphertext</th>
                {cols.map((p) => (
                  <th key={p} className="pcol">
                    <ProviderName name={p} />
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {d.chunks.map((c) => (
                <tr key={c.index}>
                  <td className="num mono">{c.index}</td>
                  <td>
                    <Hash value={c.chunk_id} n={10} />
                  </td>
                  <td className="num">{bytes(c.ciphertext_size)}</td>
                  {cols.map((p) => {
                    const r = c.replicas.find((x) => x.provider === p);
                    return (
                      <td key={p} className={`gcell ${r ? `g-${r.status}` : "g-none"}`} style={{ ["--pc" as string]: providerColor(p) }}>
                        {r ? (
                          <span title={`stored ${time(r.stored_at)}; last verified ${time(r.last_verified_at)}`}>
                            <span className="gmark" aria-hidden />
                            {r.status}
                          </span>
                        ) : (
                          <span className="muted" aria-label="no replica">
                            ·
                          </span>
                        )}
                      </td>
                    );
                  })}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </>
  );
}

function MetricsTable({ m }: { m: StorageMetrics }) {
  const rows: { p: string; op: string; c: StorageMetrics["counters"][string][string]; avg: number | null }[] = [];
  for (const [p, ops] of Object.entries(m.counters)) {
    for (const [op, c] of Object.entries(ops)) {
      const l = m.latency[p]?.[op];
      rows.push({ p, op, c, avg: l && l.count ? (l.sum_seconds / l.count) * 1000 : null });
    }
  }
  if (rows.length === 0) return <Empty>No storage operations recorded since the server started.</Empty>;
  rows.sort((a, b) => a.p.localeCompare(b.p) || a.op.localeCompare(b.op));
  return (
    <div className="table-wrap">
      <table className="table tight">
        <thead>
          <tr>
            <th>Provider</th>
            <th>Operation</th>
            <th className="num">Attempts</th>
            <th className="num">OK</th>
            <th className="num">Failed</th>
            <th className="num">Retries</th>
            <th className="num">Avg ms</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr key={`${r.p}/${r.op}`}>
              <td>
                <ProviderName name={r.p} />
              </td>
              <td>
                <code>{r.op}</code>
              </td>
              <td className="num">{num(r.c.attempts)}</td>
              <td className="num">{num(r.c.successes)}</td>
              <td className={`num${r.c.failures ? " crit-text" : ""}`}>{num(r.c.failures)}</td>
              <td className="num">{num(r.c.retries)}</td>
              <td className="num">{r.avg !== null ? r.avg.toFixed(1) : "–"}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <p className="muted small">Counters are per backend process and reset when it restarts.</p>
    </div>
  );
}

function FaultControls({ providers, onChange }: { providers: string[]; onChange: () => void }) {
  const [faults, setFaults] = useState<FaultStatus[] | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const [provider, setProvider] = useState(providers[0] ?? "");
  const [mode, setMode] = useState<FaultMode>("unavailable");
  const [n, setN] = useState(3);
  const [delay, setDelay] = useState(2);

  async function act(fn: () => Promise<unknown>) {
    setBusy(true);
    setError(null);
    try {
      await fn();
      const r = await api.get<{ faults: FaultStatus[] }>("/api/storage/faults");
      setFaults(r.faults);
      onChange();
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Panel className="sim" title="SIMULATED FAULT injection (demo only)">
      <p className="small">
        These controls make the backend pretend a provider is failing, to demonstrate failover, repair and integrity checks. They are
        not real outages, are audited as <code>storage.fault.set</code>, and need a recent MFA check.
      </p>
      {!faults ? (
        <button className="btn" disabled={busy} onClick={() => void act(async () => undefined)}>
          {busy ? "Loading…" : "Show fault controls"}
        </button>
      ) : (
        <>
          <table className="table tight">
            <thead>
              <tr>
                <th>Provider</th>
                <th>Mode</th>
                <th>Params</th>
                <th className="num">Remaining</th>
                <th className="num">Injected failures</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {faults.map((f) => (
                <tr key={f.provider}>
                  <td>
                    <ProviderName name={f.provider} />
                  </td>
                  <td>{f.injected ? <Pill tone="crit">SIMULATED {f.mode}</Pill> : <span className="muted">{f.mode}</span>}</td>
                  <td className="mono small">{Object.keys(f.params ?? {}).length ? JSON.stringify(f.params) : "–"}</td>
                  <td className="num">{f.remaining_failures ?? "–"}</td>
                  <td className="num">{num(f.injected_failures_total)}</td>
                  <td>
                    {f.injected && (
                      <button className="btn small" disabled={busy} onClick={() => void act(() => api.del(`/api/storage/faults/${encodeURIComponent(f.provider)}`))}>
                        Clear
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <form
            className="row wrap"
            onSubmit={(e) => {
              e.preventDefault();
              const body: Record<string, unknown> = { mode };
              if (mode === "fail-n") body.n = n;
              if (mode === "slow" || mode === "timeout") body.delay = delay;
              void act(() => api.put(`/api/storage/faults/${encodeURIComponent(provider)}`, body));
            }}
          >
            <label className="inline-field">
              <span>Provider</span>
              <select value={provider} onChange={(e) => setProvider(e.target.value)}>
                {providers.map((p) => (
                  <option key={p}>{p}</option>
                ))}
              </select>
            </label>
            <label className="inline-field">
              <span>Mode</span>
              <select value={mode} onChange={(e) => setMode(e.target.value as FaultMode)}>
                {FAULT_MODES.map((m) => (
                  <option key={m}>{m}</option>
                ))}
              </select>
            </label>
            {mode === "fail-n" && (
              <label className="inline-field">
                <span>n</span>
                <input type="number" min={1} max={1000} value={n} onChange={(e) => setN(Number(e.target.value))} />
              </label>
            )}
            {(mode === "slow" || mode === "timeout") && (
              <label className="inline-field">
                <span>Delay s</span>
                <input type="number" min={0} max={30} step={0.5} value={delay} onChange={(e) => setDelay(Number(e.target.value))} />
              </label>
            )}
            <button className="btn danger" disabled={busy}>
              Apply simulated fault
            </button>
          </form>
        </>
      )}
      <ErrorNotice error={error} compact />
    </Panel>
  );
}
