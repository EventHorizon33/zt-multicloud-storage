import { describe, expect, it, vi } from "vitest";
import { ApiError, createApiClient, filenameFromDisposition, parseError } from "./client";

const token = (n: number) => ({
  access_token: `tok-${n}`,
  token_type: "bearer",
  expires_in: 300,
  session_id: "s".repeat(32),
  mfa_verified: false,
  user: { id: "u", username: "alice", role: "user", clearance: "confidential", is_active: true, mfa_enabled: false, created_at: "" },
});

const json = (status: number, body: unknown, headers: Record<string, string> = {}) =>
  new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json", ...headers } });

function authOf(init?: RequestInit): string | null {
  return new Headers(init?.headers).get("Authorization");
}

describe("parseError", () => {
  it("reads error, reasons, request_id, obligations and Retry-After", async () => {
    const err = await parseError(
      json(429, { error: "rate-limited", reasons: ["login"], request_id: "req-1" }, { "Retry-After": "17" }),
    );
    expect(err).toBeInstanceOf(ApiError);
    expect(err.status).toBe(429);
    expect(err.code).toBe("rate-limited");
    expect(err.reasons).toEqual(["login"]);
    expect(err.requestId).toBe("req-1");
    expect(err.retryAfter).toBe(17);
  });

  it("detects step-up from obligations and reasons", async () => {
    const a = await parseError(json(403, { error: "access-denied", reasons: ["mfa-stale"], request_id: "r", obligations: ["step-up-mfa"] }));
    expect(a.needsStepUp).toBe(true);
    const b = await parseError(json(403, { error: "access-denied", reasons: ["insufficient-clearance"], request_id: "r" }));
    expect(b.needsStepUp).toBe(false);
  });

  it("tolerates a non-JSON body and keeps X-Request-ID", async () => {
    const err = await parseError(new Response("<html>bad gateway</html>", { status: 502, headers: { "X-Request-ID": "abc12345" } }));
    expect(err.code).toBe("http-502");
    expect(err.reasons).toEqual([]);
    expect(err.requestId).toBe("abc12345");
  });
});

describe("refresh on 401", () => {
  it("refreshes once for concurrent 401s (single flight) and retries each request once", async () => {
    let refreshCalls = 0;
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const u = String(input);
      if (u === "/api/auth/refresh") {
        refreshCalls++;
        await new Promise((r) => setTimeout(r, 10));
        return json(200, token(2));
      }
      return authOf(init) === "Bearer tok-2" ? json(200, { ok: u }) : json(401, { error: "unauthenticated", reasons: [], request_id: "x" });
    });
    const c = createApiClient({ fetch: fetchMock as unknown as typeof fetch });
    c.setSession(token(1) as never);
    const results = await Promise.all([c.get("/api/a"), c.get("/api/b"), c.get("/api/c")]);
    expect(results).toEqual([{ ok: "/api/a" }, { ok: "/api/b" }, { ok: "/api/c" }]);
    expect(refreshCalls).toBe(1);
    // 3 failed + 1 refresh + 3 retries
    expect(fetchMock).toHaveBeenCalledTimes(7);
  });

  it("calls onAuthLost and throws when refresh fails", async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL) =>
      String(input) === "/api/auth/refresh"
        ? json(401, { error: "unauthenticated", reasons: [], request_id: "r1" })
        : json(401, { error: "unauthenticated", reasons: [], request_id: "r2" }),
    );
    const c = createApiClient({ fetch: fetchMock as unknown as typeof fetch });
    c.setSession(token(1) as never);
    const lost = vi.fn();
    c.onAuthLost(lost);
    await expect(c.get("/api/files")).rejects.toMatchObject({ status: 401, requestId: "r2" });
    expect(lost).toHaveBeenCalledTimes(1);
    expect(c.hasToken()).toBe(false);
  });

  it("does not loop: a second 401 after refresh ends the session", async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL) =>
      String(input) === "/api/auth/refresh" ? json(200, token(2)) : json(401, { error: "unauthenticated", reasons: [], request_id: "r" }),
    );
    const c = createApiClient({ fetch: fetchMock as unknown as typeof fetch });
    const lost = vi.fn();
    c.onAuthLost(lost);
    await expect(c.get("/api/x")).rejects.toBeInstanceOf(ApiError);
    expect(fetchMock).toHaveBeenCalledTimes(3);
    expect(lost).toHaveBeenCalledTimes(1);
  });

  it("does not refresh for anonymous calls such as login", async () => {
    const fetchMock = vi.fn(async () => json(401, { error: "unauthenticated", reasons: ["mfa-required"], request_id: "r" }));
    const c = createApiClient({ fetch: fetchMock as unknown as typeof fetch });
    await expect(c.post("/api/auth/login", { username: "a", password: "b" }, { anonymous: true })).rejects.toMatchObject({
      reasons: ["mfa-required"],
    });
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });
});

describe("step-up MFA", () => {
  const denied = () =>
    json(403, { error: "access-denied", reasons: ["mfa-required"], request_id: "r", obligations: ["step-up-mfa"] });

  it("opens the handler and retries once after a successful verify", async () => {
    let verified = false;
    const fetchMock = vi.fn(async () => (verified ? json(200, { file_id: "f", status: "deleted" }) : denied()));
    const c = createApiClient({ fetch: fetchMock as unknown as typeof fetch });
    const handler = vi.fn(async (e: ApiError) => {
      expect(e.needsStepUp).toBe(true);
      verified = true;
      return true;
    });
    c.setStepUpHandler(handler);
    await expect(c.del("/api/files/f")).resolves.toEqual({ file_id: "f", status: "deleted" });
    expect(handler).toHaveBeenCalledTimes(1);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("surfaces the 403 when the user cancels", async () => {
    const fetchMock = vi.fn(async () => denied());
    const c = createApiClient({ fetch: fetchMock as unknown as typeof fetch });
    c.setStepUpHandler(async () => false);
    await expect(c.del("/api/files/f")).rejects.toMatchObject({ status: 403, code: "access-denied" });
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("retries at most once even if the server still demands MFA", async () => {
    const fetchMock = vi.fn(async () => denied());
    const c = createApiClient({ fetch: fetchMock as unknown as typeof fetch });
    const handler = vi.fn(async () => true);
    c.setStepUpHandler(handler);
    await expect(c.del("/api/files/f")).rejects.toMatchObject({ status: 403 });
    expect(handler).toHaveBeenCalledTimes(1);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("password change: 403 mfa-stale + step-up-mfa opens the dialog and resends the same body (H1)", async () => {
    let verified = false;
    const bodies: string[] = [];
    const fetchMock = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      bodies.push(String(init?.body));
      return verified
        ? json(200, { sessions_revoked: 1 })
        : json(403, { error: "access-denied", reasons: ["mfa-stale"], request_id: "r", obligations: ["step-up-mfa"] });
    });
    const c = createApiClient({ fetch: fetchMock as unknown as typeof fetch });
    const handler = vi.fn(async () => {
      verified = true;
      return true;
    });
    c.setStepUpHandler(handler);
    const body = { current_password: "old-Passw0rd-xx", new_password: "new-Passw0rd-yy" };
    await expect(c.post("/api/auth/password", body)).resolves.toEqual({ sessions_revoked: 1 });
    expect(handler).toHaveBeenCalledTimes(1);
    expect(bodies).toHaveLength(2);
    expect(JSON.parse(bodies[1])).toEqual(body);
  });

  it("password change without a factor (enroll-mfa) does not open the dialog", async () => {
    const fetchMock = vi.fn(async () =>
      json(403, { error: "access-denied", reasons: ["mfa-required"], request_id: "r", obligations: ["enroll-mfa"] }),
    );
    const c = createApiClient({ fetch: fetchMock as unknown as typeof fetch });
    const handler = vi.fn(async () => true);
    c.setStepUpHandler(handler);
    await expect(c.post("/api/auth/password", { current_password: "a", new_password: "b" })).rejects.toMatchObject({
      status: 403,
      reasons: ["mfa-required"],
    });
    expect(handler).not.toHaveBeenCalled();
  });

  it("does not open the dialog when the user must enrol MFA first", async () => {
    const fetchMock = vi.fn(async () =>
      json(403, { error: "access-denied", reasons: ["mfa-required"], request_id: "r", obligations: ["step-up-mfa", "enroll-mfa"] }),
    );
    const c = createApiClient({ fetch: fetchMock as unknown as typeof fetch });
    const handler = vi.fn(async () => true);
    c.setStepUpHandler(handler);
    await expect(c.del("/api/files/f")).rejects.toMatchObject({ status: 403 });
    expect(handler).not.toHaveBeenCalled();
  });
});

describe("filenameFromDisposition", () => {
  it("prefers filename* and decodes UTF-8", () => {
    expect(filenameFromDisposition(`attachment; filename="r_sum_.pdf"; filename*=UTF-8''r%C3%A9sum%C3%A9.pdf`)).toBe("résumé.pdf");
  });
  it("falls back to filename and a default", () => {
    expect(filenameFromDisposition(`attachment; filename="a.txt"`)).toBe("a.txt");
    expect(filenameFromDisposition(null, "x.bin")).toBe("x.bin");
  });
});
