import { useCallback, useEffect, useRef, useState } from "react";
import { ApiError } from "../api/client";

export interface ApiState<T> {
  data: T | undefined;
  error: ApiError | Error | undefined;
  loading: boolean;
  reload: () => Promise<void>;
  updatedAt: number | null;
}

/**
 * Loads data from the API. `deps` re-run the loader; `intervalMs` polls (paused while the tab is hidden).
 * The last good data is kept while a background refresh fails, and the error is reported alongside it.
 */
export function useApi<T>(loader: (() => Promise<T>) | null, deps: unknown[], intervalMs?: number): ApiState<T> {
  const [data, setData] = useState<T>();
  const [error, setError] = useState<ApiError | Error>();
  const [loading, setLoading] = useState(loader !== null);
  const [updatedAt, setUpdatedAt] = useState<number | null>(null);
  const ref = useRef(loader);
  ref.current = loader;
  const gen = useRef(0);

  const reload = useCallback(async () => {
    const fn = ref.current;
    if (!fn) return;
    const my = ++gen.current;
    setLoading(true);
    try {
      const d = await fn();
      if (my !== gen.current) return;
      setData(d);
      setError(undefined);
      setUpdatedAt(Date.now());
    } catch (e) {
      if (my !== gen.current) return;
      setError(e instanceof Error ? e : new Error(String(e)));
    } finally {
      if (my === gen.current) setLoading(false);
    }
  }, []);

  useEffect(() => {
    setData(undefined);
    setError(undefined);
    if (!ref.current) {
      setLoading(false);
      return;
    }
    void reload();
    if (!intervalMs) return;
    const t = window.setInterval(() => {
      if (document.visibilityState === "visible") void reload();
    }, intervalMs);
    return () => window.clearInterval(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);

  return { data, error, loading, reload, updatedAt };
}
