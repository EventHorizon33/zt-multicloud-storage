import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The backend (scripts/run-dev.sh) listens on 127.0.0.1:8000. Proxying /api and
// /metrics keeps the SPA and the API on one origin, so the HttpOnly refresh
// cookie (Path=/api/auth, SameSite=Strict) is sent by the browser.
const BACKEND = process.env.ZT_BACKEND_URL ?? "http://127.0.0.1:8000";
const proxy = {
  "/api": { target: BACKEND, changeOrigin: false },
  "/metrics": { target: BACKEND, changeOrigin: false },
};

export default defineConfig({
  plugins: [react()],
  server: { host: "127.0.0.1", port: 5173, strictPort: true, proxy },
  preview: { host: "127.0.0.1", port: 4173, strictPort: true, proxy },
  build: { sourcemap: false, target: "es2022" },
  test: { environment: "jsdom", include: ["src/**/*.test.ts"] },
});
