export function bytes(n: number | null | undefined): string {
  if (n === null || n === undefined || !Number.isFinite(n)) return "–";
  if (n < 1024) return `${n} B`;
  const units = ["KiB", "MiB", "GiB", "TiB"];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(v < 10 ? 1 : 0)} ${units[i]}`;
}

export function num(n: number | null | undefined): string {
  if (n === null || n === undefined) return "–";
  return n.toLocaleString("en-US");
}

/** Timestamps from the API are UTC ISO strings; shown in local time with seconds. */
export function time(iso: string | null | undefined): string {
  if (!iso) return "–";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

export function ago(iso: string | null | undefined, now = Date.now()): string {
  if (!iso) return "never";
  const t = new Date(iso).getTime();
  if (Number.isNaN(t)) return iso;
  const s = Math.round((now - t) / 1000);
  if (s < 0) return `in ${dur(-s)}`;
  if (s < 5) return "just now";
  return `${dur(s)} ago`;
}

export function dur(sec: number): string {
  if (sec < 60) return `${Math.round(sec)} s`;
  if (sec < 3600) return `${Math.round(sec / 60)} min`;
  if (sec < 86400) return `${(sec / 3600).toFixed(sec < 36000 ? 1 : 0)} h`;
  return `${(sec / 86400).toFixed(1)} d`;
}

export function short(id: string | null | undefined, n = 8): string {
  if (!id) return "–";
  return id.length > n + 2 ? `${id.slice(0, n)}…` : id;
}

/** A stable hue derived from a hex hash, so equal hashes look equal at a glance. */
export function hashHue(hex: string): number {
  const v = parseInt(hex.slice(0, 6), 16);
  return Number.isNaN(v) ? 0 : v % 360;
}

export async function sha256Hex(data: ArrayBuffer): Promise<string> {
  const d = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(d), (b) => b.toString(16).padStart(2, "0")).join("");
}
