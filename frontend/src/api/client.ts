// HTTP client for the zero-trust storage API.
//
// * The access token lives only in this closure (never in web storage).
// * On 401 the client performs ONE refresh through the HttpOnly cookie endpoint,
//   shared by every request that failed at the same time (single flight), then
//   retries the original request once. If the refresh fails the session is gone
//   and `onAuthLost` is called (the app shows the login screen).
// * On 403 with `mfa-required` / `mfa-stale` / obligation `step-up-mfa` the
//   registered step-up handler is asked to verify a TOTP code; if it reports
//   success the request is retried once.
// * Every non-2xx response becomes an ApiError carrying the server's
//   {error, reasons, request_id, obligations} body.

import type { TokenResponse } from "./types";

export interface ErrorBody {
  error: string;
  reasons: string[];
  request_id: string | null;
  obligations?: string[];
}

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly reasons: string[];
  readonly requestId: string | null;
  readonly obligations: string[];
  readonly retryAfter: number | null;

  constructor(status: number, body: ErrorBody, retryAfter: number | null = null) {
    super(`${status} ${body.error}${body.reasons.length ? ` (${body.reasons.join(", ")})` : ""}`);
    this.name = "ApiError";
    this.status = status;
    this.code = body.error;
    this.reasons = body.reasons;
    this.requestId = body.request_id;
    this.obligations = body.obligations ?? [];
    this.retryAfter = retryAfter;
  }

  has(reason: string): boolean {
    return this.reasons.includes(reason) || this.obligations.includes(reason);
  }

  /** The server says a fresh second factor would allow this request. */
  get needsStepUp(): boolean {
    return (
      this.status === 403 &&
      (this.obligations.includes("step-up-mfa") || this.reasons.includes("mfa-required") || this.reasons.includes("mfa-stale"))
    );
  }
}

/** Parse an error response into an ApiError, tolerating non-JSON bodies (e.g. a proxy 502 page). */
export async function parseError(res: Response): Promise<ApiError> {
  let body: ErrorBody = { error: `http-${res.status}`, reasons: [], request_id: res.headers.get("X-Request-ID") };
  try {
    const text = await res.text();
    if (text) {
      const data: unknown = JSON.parse(text);
      if (data && typeof data === "object" && typeof (data as { error?: unknown }).error === "string") {
        const d = data as Partial<ErrorBody>;
        body = {
          error: d.error as string,
          reasons: Array.isArray(d.reasons) ? d.reasons.filter((r): r is string => typeof r === "string") : [],
          request_id: typeof d.request_id === "string" ? d.request_id : body.request_id,
          obligations: Array.isArray(d.obligations) ? d.obligations.filter((r): r is string => typeof r === "string") : undefined,
        };
      }
    }
  } catch {
    /* not JSON: keep the generic body */
  }
  const ra = res.headers.get("Retry-After");
  const retryAfter = ra !== null && /^\d+$/.test(ra) ? Number(ra) : null;
  return new ApiError(res.status, body, retryAfter);
}

/** Sends one HTTP attempt. The default uses fetch; uploads plug in an XHR transport for progress. */
export type Transport = (url: string, init: RequestInit) => Promise<Response>;

export interface RequestOptions {
  method?: string;
  json?: unknown;
  body?: BodyInit;
  query?: Record<string, string | number | boolean | undefined | null>;
  signal?: AbortSignal;
  transport?: Transport;
  /** Do not attach the bearer token nor attempt refresh (login/register). */
  anonymous?: boolean;
  /** Do not open the step-up dialog on 403 mfa-required (e.g. the dialog's own verify call). */
  noStepUp?: boolean;
}

export type StepUpHandler = (err: ApiError) => Promise<boolean>;

export interface ApiClientOptions {
  fetch?: typeof fetch;
  baseUrl?: string;
}

export function createApiClient(opts: ApiClientOptions = {}) {
  const doFetch: typeof fetch = opts.fetch ?? ((input, init) => globalThis.fetch(input, init));
  const base = opts.baseUrl ?? "";
  let accessToken: string | null = null;
  let refreshing: Promise<TokenResponse | null> | null = null;
  let stepUpHandler: StepUpHandler | null = null;
  let stepUpInFlight: Promise<boolean> | null = null;
  const tokenListeners = new Set<(t: TokenResponse | null) => void>();
  let authLost: (() => void) | null = null;

  function url(path: string, query?: RequestOptions["query"]): string {
    let u = base + path;
    if (query) {
      const p = new URLSearchParams();
      for (const [k, v] of Object.entries(query)) {
        if (v !== undefined && v !== null && v !== "") p.set(k, String(v));
      }
      const qs = p.toString();
      if (qs) u += (u.includes("?") ? "&" : "?") + qs;
    }
    return u;
  }

  function setSession(t: TokenResponse | null) {
    accessToken = t ? t.access_token : null;
    for (const l of tokenListeners) l(t);
  }

  /** Single-flight refresh: concurrent callers share one POST /api/auth/refresh. */
  function refresh(): Promise<TokenResponse | null> {
    if (!refreshing) {
      refreshing = (async () => {
        try {
          const res = await doFetch(url("/api/auth/refresh"), { method: "POST", credentials: "include" });
          if (!res.ok) {
            setSession(null);
            return null;
          }
          const t = (await res.json()) as TokenResponse;
          setSession(t);
          return t;
        } catch {
          setSession(null);
          return null;
        } finally {
          refreshing = null;
        }
      })();
    }
    return refreshing;
  }

  async function attempt(path: string, o: RequestOptions): Promise<Response> {
    const headers = new Headers();
    let body: BodyInit | undefined = o.body;
    if (o.json !== undefined) {
      headers.set("Content-Type", "application/json");
      body = JSON.stringify(o.json);
    }
    if (!o.anonymous && accessToken) headers.set("Authorization", `Bearer ${accessToken}`);
    const init: RequestInit = { method: o.method ?? "GET", headers, body, signal: o.signal, credentials: "same-origin" };
    return (o.transport ?? doFetch)(url(path, o.query), init);
  }

  /** Returns the raw successful Response; throws ApiError otherwise. */
  async function raw(path: string, o: RequestOptions = {}): Promise<Response> {
    let res = await attempt(path, o);

    if (res.status === 401 && !o.anonymous) {
      const t = await refresh();
      if (!t) {
        authLost?.();
        throw await parseError(res);
      }
      res = await attempt(path, o);
      if (res.status === 401) {
        setSession(null);
        authLost?.();
        throw await parseError(res);
      }
    }

    if (!res.ok) {
      const err = await parseError(res);
      if (err.needsStepUp && !o.noStepUp && stepUpHandler && !err.obligations.includes("enroll-mfa")) {
        // One dialog for all concurrent step-up demands.
        if (!stepUpInFlight) {
          stepUpInFlight = stepUpHandler(err).finally(() => {
            stepUpInFlight = null;
          });
        }
        const ok = await stepUpInFlight;
        // Retry once; the retry goes through the full pipeline (401 refresh) but never re-opens the dialog.
        if (ok) return raw(path, { ...o, noStepUp: true });
      }
      throw err;
    }
    return res;
  }

  async function json<T>(path: string, o: RequestOptions = {}): Promise<T> {
    const res = await raw(path, o);
    if (res.status === 204) return undefined as T;
    const text = await res.text();
    return (text ? JSON.parse(text) : undefined) as T;
  }

  return {
    raw,
    json,
    refresh,
    get: <T>(path: string, query?: RequestOptions["query"]) => json<T>(path, { query }),
    post: <T>(path: string, body?: unknown, extra: RequestOptions = {}) => json<T>(path, { method: "POST", json: body, ...extra }),
    put: <T>(path: string, body?: unknown) => json<T>(path, { method: "PUT", json: body }),
    del: <T>(path: string) => json<T>(path, { method: "DELETE" }),
    setSession,
    hasToken: () => accessToken !== null,
    onToken(l: (t: TokenResponse | null) => void) {
      tokenListeners.add(l);
      return () => tokenListeners.delete(l);
    },
    onAuthLost(cb: (() => void) | null) {
      authLost = cb;
    },
    setStepUpHandler(h: StepUpHandler | null) {
      stepUpHandler = h;
    },
  };
}

export type ApiClient = ReturnType<typeof createApiClient>;

/** XHR transport so uploads can report progress. Returns a real Response so the client pipeline is unchanged. */
export function xhrTransport(onProgress: (loaded: number, total: number) => void): Transport {
  return (url, init) =>
    new Promise<Response>((resolve, reject) => {
      const xhr = new XMLHttpRequest();
      xhr.open(init.method ?? "GET", url);
      xhr.responseType = "blob";
      new Headers(init.headers).forEach((v, k) => xhr.setRequestHeader(k, v));
      xhr.upload.onprogress = (e) => onProgress(e.loaded, e.lengthComputable ? e.total : 0);
      xhr.onload = () => {
        const headers = new Headers();
        for (const line of xhr.getAllResponseHeaders().trim().split(/[\r\n]+/)) {
          const i = line.indexOf(":");
          if (i > 0) headers.append(line.slice(0, i).trim(), line.slice(i + 1).trim());
        }
        const status = xhr.status;
        const nullBody = status === 204 || status === 205 || status === 304;
        resolve(new Response(nullBody ? null : (xhr.response as Blob), { status, headers }));
      };
      xhr.onerror = () => reject(new TypeError("network error"));
      xhr.onabort = () => reject(new DOMException("aborted", "AbortError"));
      init.signal?.addEventListener("abort", () => xhr.abort());
      xhr.send((init.body as XMLHttpRequestBodyInit | null | undefined) ?? null);
    });
}

/** Filename from Content-Disposition (RFC 6266: prefers filename*=UTF-8''…). */
export function filenameFromDisposition(h: string | null, fallback = "download.bin"): string {
  if (!h) return fallback;
  const star = /filename\*\s*=\s*UTF-8''([^;]+)/i.exec(h);
  if (star) {
    try {
      return decodeURIComponent(star[1].trim());
    } catch {
      /* fall through */
    }
  }
  const plain = /filename\s*=\s*"([^"]*)"/i.exec(h) ?? /filename\s*=\s*([^;]+)/i.exec(h);
  return plain ? plain[1].trim() : fallback;
}

export const api = createApiClient();
