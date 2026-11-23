import { useCallback, useEffect, useRef, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api, ApiError, filenameFromDisposition, xhrTransport } from "../api/client";
import { CLASSIFICATIONS, type Classification, type FileList, type FileRow, type RepairReport, type Share, type VerifyReport } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { Empty, ErrorNotice, Hash, KV, PageHead, Panel, Pill, ProviderName, statusTone, Updated } from "../components/ui";
import { bytes, sha256Hex, time } from "../lib/format";
import { useApi } from "../lib/useApi";

const RANK: Record<Classification, number> = { public: 0, internal: 1, confidential: 2, restricted: 3 };

export function Files() {
  const list = useApi(() => api.get<FileList>("/api/files"), [], 15_000);
  const [params, setParams] = useSearchParams();
  const selectedId = params.get("file");
  const files = list.data?.files ?? [];
  const selected = files.find((f) => f.id === selectedId) ?? null;
  const select = (id: string | null) => setParams(id ? { file: id } : {}, { replace: true });
  const [flash, setFlash] = useState<string | null>(null);

  return (
    <div className="page">
      <PageHead title="Files" sub="Files are split into 1 MiB chunks, encrypted with a per-file key and spread over the providers.">
        <Updated at={list.updatedAt} loading={list.loading} />
      </PageHead>
      <Uploader onUploaded={(f) => { setFlash(null); void list.reload(); select(f.id); }} />
      {flash && <div className="notice notice-ok" role="status">{flash}</div>}
      <div className={`split${selected ? " with-side" : ""}`}>
        <Panel title={`Your files and files shared with you${list.data ? ` (${list.data.total})` : ""}`}>
          <ErrorNotice error={list.error} onRetry={() => void list.reload()} />
          {list.data && files.length === 0 && <Empty>No files yet. Upload one above.</Empty>}
          {files.length > 0 && (
            <div className="table-wrap">
              <table className="table clickable" aria-label="Files">
                <thead>
                  <tr>
                    <th>Name</th>
                    <th className="num">Size</th>
                    <th>Classification</th>
                    <th>Status</th>
                    <th className="num">Chunks</th>
                    <th>Owner</th>
                    <th>Created</th>
                  </tr>
                </thead>
                <tbody>
                  {files.map((f) => (
                    <tr
                      key={f.id}
                      className={f.id === selectedId ? "sel" : undefined}
                      onClick={() => select(f.id)}
                      tabIndex={0}
                      onKeyDown={(e) => e.key === "Enter" && select(f.id)}
                    >
                      <td className="name-cell">
                        {f.filename ?? <span className="muted">name hidden ({f.status})</span>}
                        {f.metadata_error && <Pill tone="crit">{f.metadata_error}</Pill>}
                      </td>
                      <td className="num">{bytes(f.size_bytes)}</td>
                      <td>
                        <ClassPill c={f.classification} />
                      </td>
                      <td>
                        <Pill tone={statusTone(f.status)}>{f.status}</Pill>
                        {f.failure_reason && <span className="muted tiny"> {f.failure_reason}</span>}
                      </td>
                      <td className="num">{f.chunk_count}</td>
                      <td>{f.is_owner ? <span className="muted">you</span> : <span>{f.owner_username ?? "–"} <Pill tone="info">shared</Pill></span>}</td>
                      <td className="nowrap">{time(f.created_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Panel>
        {selected && (
          <FilePanel
            key={selected.id}
            file={selected}
            onClose={() => select(null)}
            onChanged={() => void list.reload()}
            onDeleted={(msg) => {
              setFlash(msg);
              select(null);
              void list.reload();
            }}
          />
        )}
      </div>
      {selectedId && list.data && !selected && !flash && (
        <div className="notice notice-info">The selected file is not in your list (deleted, or not shared with you).</div>
      )}
    </div>
  );
}

export function ClassPill({ c }: { c: Classification }) {
  return <span className={`cls cls-${c}`}>{c}</span>;
}

function Uploader({ onUploaded }: { onUploaded: (f: FileRow) => void }) {
  const { me } = useAuth();
  const clearance = me?.user.clearance ?? "internal";
  const [cls, setCls] = useState<Classification>("internal");
  const [file, setFile] = useState<File | null>(null);
  const [progress, setProgress] = useState<number | null>(null);
  const [phase, setPhase] = useState<"idle" | "sending" | "processing">("idle");
  const [error, setError] = useState<unknown>(null);
  const [done, setDone] = useState<FileRow | null>(null);
  const [drag, setDrag] = useState(false);
  const input = useRef<HTMLInputElement>(null);
  const abort = useRef<AbortController | null>(null);

  async function upload() {
    if (!file) return;
    setError(null);
    setDone(null);
    setPhase("sending");
    setProgress(0);
    const form = new FormData();
    form.append("classification", cls); // must precede the file part
    form.append("file", file, file.name);
    abort.current = new AbortController();
    try {
      const f = await api.json<FileRow>("/api/files", {
        method: "POST",
        body: form,
        query: { classification: cls },
        signal: abort.current.signal,
        transport: xhrTransport((loaded, total) => {
          const p = total ? loaded / total : 0;
          setProgress(p);
          if (p >= 1) setPhase("processing");
        }),
      });
      setDone(f);
      setFile(null);
      if (input.current) input.current.value = "";
      onUploaded(f);
    } catch (e) {
      setError(e);
    } finally {
      setPhase("idle");
      setProgress(null);
      abort.current = null;
    }
  }

  return (
    <Panel title="Upload">
      <div
        className={`drop${drag ? " over" : ""}`}
        onDragOver={(e) => {
          e.preventDefault();
          setDrag(true);
        }}
        onDragLeave={() => setDrag(false)}
        onDrop={(e) => {
          e.preventDefault();
          setDrag(false);
          const f = e.dataTransfer.files[0];
          if (f) setFile(f);
        }}
      >
        <div className="drop-main">
          <input ref={input} id="file-input" type="file" className="sr-only" onChange={(e) => setFile(e.target.files?.[0] ?? null)} />
          <label htmlFor="file-input" className="btn">
            Choose file
          </label>
          <span className={file ? "" : "muted"}>{file ? `${file.name} (${bytes(file.size)})` : "or drop a file here"}</span>
        </div>
        <div className="row wrap">
          <label className="inline-field">
            <span>Classification</span>
            <select value={cls} onChange={(e) => setCls(e.target.value as Classification)} name="classification">
              {CLASSIFICATIONS.map((c) => (
                <option key={c} value={c}>
                  {c}
                  {RANK[c] > RANK[clearance] ? " (above your clearance)" : ""}
                </option>
              ))}
            </select>
          </label>
          {phase === "idle" ? (
            <button className="btn primary" disabled={!file} onClick={() => void upload()}>
              Upload
            </button>
          ) : (
            <button className="btn ghost" onClick={() => abort.current?.abort()}>
              Cancel
            </button>
          )}
        </div>
      </div>
      {progress !== null && (
        <div className="progress" role="progressbar" aria-valuenow={Math.round(progress * 100)} aria-valuemin={0} aria-valuemax={100}>
          <div className="progress-fill" style={{ width: `${progress * 100}%` }} />
          <span className="progress-text">
            {phase === "processing" ? "Encrypting and distributing chunks on the server…" : `Sending ${Math.round(progress * 100)} %`}
          </span>
        </div>
      )}
      {RANK[cls] >= RANK.confidential && <p className="hint">Downloading {cls} files requires a recent MFA check under the default policy.</p>}
      <ErrorNotice error={error} compact />
      {done && (
        <div className="notice notice-ok">
          Stored <b>{done.filename}</b> as {done.chunk_count} encrypted chunk{done.chunk_count === 1 ? "" : "s"}.{" "}
          <Link to={`/distribution?file=${done.id}`}>See where the chunks went</Link>
        </div>
      )}
    </Panel>
  );
}

interface DownloadResult {
  name: string;
  size: number;
  serverSha: string | null;
  localSha: string;
  url: string;
}

function FilePanel({ file, onClose, onChanged, onDeleted }: { file: FileRow; onClose: () => void; onChanged: () => void; onDeleted: (msg: string) => void }) {
  const committed = file.status === "committed";
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [dl, setDl] = useState<DownloadResult | null>(null);
  const [compare, setCompare] = useState("");
  const [verify, setVerify] = useState<VerifyReport | null>(null);
  const [repair, setRepair] = useState<RepairReport | null>(null);

  useEffect(() => () => { if (dl) URL.revokeObjectURL(dl.url); }, [dl]);

  const run = useCallback(async (name: string, fn: () => Promise<void>) => {
    setBusy(name);
    setError(null);
    try {
      await fn();
    } catch (e) {
      setError(e);
    } finally {
      setBusy(null);
    }
  }, []);

  const download = () =>
    run("download", async () => {
      const res = await api.raw(`/api/files/${file.id}/download`);
      const blob = await res.blob();
      const localSha = await sha256Hex(await blob.arrayBuffer());
      const name = filenameFromDisposition(res.headers.get("Content-Disposition"), file.filename ?? "download.bin");
      const url = URL.createObjectURL(blob);
      setDl({ name, size: blob.size, serverSha: res.headers.get("X-Content-SHA256"), localSha, url });
      const a = document.createElement("a");
      a.href = url;
      a.download = name;
      a.rel = "noopener";
      document.body.appendChild(a);
      a.click();
      a.remove();
    });

  const doDelete = () =>
    run("delete", async () => {
      if (!window.confirm(`Delete ${file.filename ?? file.id}? The file key is destroyed; this cannot be undone.`)) return;
      const r = await api.del<{ file_id: string; status: string; leftover_replicas: number }>(`/api/files/${file.id}`);
      onDeleted(
        `Deleted ${file.filename ?? file.id}. Key destroyed${r.leftover_replicas > 0 ? `; ${r.leftover_replicas} replica(s) will be removed by background retry` : ""}.`,
      );
    });

  const cmp = compare.trim().toLowerCase();
  return (
    <Panel
      className="side"
      title={file.filename ?? "File"}
      actions={
        <button className="icon-btn" onClick={onClose} aria-label="Close file details">
          ×
        </button>
      }
    >
      <KV
        rows={[
          ["File ID", <Hash value={file.id} n={12} />],
          ["Type", file.mime_type ?? "–"],
          ["Size", `${bytes(file.size_bytes)} (${file.size_bytes.toLocaleString()} bytes)`],
          ["Classification", <ClassPill c={file.classification} />],
          ["Status", <Pill tone={statusTone(file.status)}>{file.status}</Pill>],
          ["Chunks", `${file.chunk_count} × ${bytes(file.chunk_size)} max`],
          ["Owner", file.is_owner ? "you" : file.owner_username ?? "–"],
          ["Created", time(file.created_at)],
          ["Committed", time(file.committed_at)],
          ...(file.failure_reason ? ([["Failure", <code>{file.failure_reason}</code>]] as [string, React.ReactNode][]) : []),
          ...(file.metadata_error ? ([["Metadata", <Pill tone="crit">{file.metadata_error}</Pill>]] as [string, React.ReactNode][]) : []),
        ]}
      />
      <>
          <div className="actions">
            <button className="btn primary" disabled={!committed || !!busy} onClick={() => void download()}>
              {busy === "download" ? "Downloading…" : "Download"}
            </button>
            <button
              className="btn"
              disabled={!committed || !!busy}
              onClick={() => void run("verify", async () => { setVerify(await api.post<VerifyReport>(`/api/files/${file.id}/verify`)); })}
              title="Read every replica's ciphertext and check its hash (no decryption)"
            >
              {busy === "verify" ? "Verifying…" : "Verify replicas"}
            </button>
            <button
              className="btn"
              disabled={!committed || !!busy}
              onClick={() => void run("repair", async () => { setRepair(await api.post<RepairReport>(`/api/files/${file.id}/repair`)); onChanged(); })}
            >
              {busy === "repair" ? "Repairing…" : "Repair"}
            </button>
            <Link className="btn ghost" to={`/distribution?file=${file.id}`}>
              Chunk map
            </Link>
            {file.is_owner && (
              <button className="btn danger" disabled={!!busy || file.status === "deleting"} onClick={() => void doDelete()}>
                {busy === "delete" ? "Deleting…" : "Delete"}
              </button>
            )}
          </div>
          {!committed && <p className="hint">Only committed files can be downloaded, verified, repaired or shared.</p>}
          <ErrorNotice error={error} compact />

          {dl && (
            <div className="subpanel">
              <h3>Download integrity</h3>
              <p className="small">
                Saved <b>{dl.name}</b> ({bytes(dl.size)}). The server verified every chunk before releasing the file and sent the
                plaintext SHA-256; the browser hashed what it received.
              </p>
              <KV
                rows={[
                  ["Server SHA-256", dl.serverSha ? <code className="wrap-hash">{dl.serverSha}</code> : <span className="warn-text">header missing</span>],
                  ["Computed here", <code className="wrap-hash">{dl.localSha}</code>],
                  [
                    "Result",
                    dl.serverSha === dl.localSha ? <Pill tone="ok">match</Pill> : <Pill tone="crit">MISMATCH</Pill>,
                  ],
                ]}
              />
              <label className="field">
                <span>Compare with a hash you trust (e.g. computed before upload)</span>
                <input value={compare} onChange={(e) => setCompare(e.target.value)} placeholder="64 hex characters" className="mono" />
              </label>
              {cmp && (
                <div>{cmp === dl.localSha ? <Pill tone="ok">matches the downloaded content</Pill> : <Pill tone="crit">does not match</Pill>}</div>
              )}
              <a className="small" href={dl.url} download={dl.name}>
                Save again
              </a>
            </div>
          )}

          {verify && (
            <div className="subpanel">
              <h3>
                Replica check{" "}
                <Pill tone={verify.healthy ? "ok" : verify.recoverable ? "warn" : "crit"}>
                  {verify.healthy ? "healthy" : verify.recoverable ? "degraded, recoverable" : "unrecoverable"}
                </Pill>
              </h3>
              <p className="small muted">
                ok {verify.summary.ok}, corrupt {verify.summary.corrupt}, missing {verify.summary.missing}, unavailable {verify.summary.unavailable}
              </p>
              <table className="table tight">
                <thead>
                  <tr>
                    <th className="num">#</th>
                    <th>Chunk</th>
                    <th>Replicas</th>
                  </tr>
                </thead>
                <tbody>
                  {verify.chunks.map((c) => (
                    <tr key={c.index}>
                      <td className="num">{c.index}</td>
                      <td>
                        <Hash value={c.chunk_id} n={8} />
                      </td>
                      <td>
                        <div className="row wrap">
                          {c.replicas.map((r) => (
                            <span key={r.provider} className="row tight">
                              <ProviderName name={r.provider} /> <Pill tone={statusTone(r.result)}>{r.result}</Pill>
                            </span>
                          ))}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {repair && (
            <div className={`notice ${repair.ok ? "notice-ok" : "notice-err"}`}>
              Repair {repair.ok ? "finished" : "incomplete"}: repaired chunks [{repair.repaired_chunks.join(", ") || "none"}], unrepairable [
              {repair.unrepairable_chunks.join(", ") || "none"}].
            </div>
          )}

          {file.is_owner && committed && <Shares fileId={file.id} />}
      </>
    </Panel>
  );
}

function Shares({ fileId }: { fileId: string }) {
  const q = useApi(() => api.get<{ shares: Share[] }>(`/api/files/${fileId}/shares`), [fileId]);
  const [user, setUser] = useState("");
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);

  async function act(fn: () => Promise<unknown>) {
    setBusy(true);
    setError(null);
    try {
      await fn();
      await q.reload();
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="subpanel">
      <h3>Sharing</h3>
      <ErrorNotice error={q.error} compact />
      {q.data && q.data.shares.length === 0 && <p className="muted small">Not shared with anyone.</p>}
      {q.data && q.data.shares.length > 0 && (
        <ul className="plain-list">
          {q.data.shares.map((s) => (
            <li key={s.username} className="row between">
              <span>
                <b>{s.username}</b> <span className="muted small">since {time(s.created_at)}</span>
              </span>
              <button
                className="btn small ghost"
                disabled={busy}
                onClick={() => void act(() => api.del(`/api/files/${fileId}/shares/${encodeURIComponent(s.username)}`))}
              >
                Unshare
              </button>
            </li>
          ))}
        </ul>
      )}
      <form
        className="row"
        onSubmit={(e) => {
          e.preventDefault();
          void act(async () => {
            await api.post(`/api/files/${fileId}/shares`, { username: user.trim() });
            setUser("");
          });
        }}
      >
        <input aria-label="Username to share with" placeholder="username" value={user} onChange={(e) => setUser(e.target.value)} required pattern="[A-Za-z0-9_.\-]{3,64}" />
        <button className="btn" disabled={busy || !user.trim()}>
          Share
        </button>
      </form>
      <p className="hint">Sharing requires a recent MFA check. The recipient must have clearance for this classification to read it.</p>
      <ErrorNotice error={error instanceof ApiError || error instanceof Error ? error : null} compact />
    </div>
  );
}
