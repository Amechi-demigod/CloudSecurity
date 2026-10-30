import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

// In dev, /api is proxied to the FastAPI backend (override with VITE_API_PROXY).
// Because the browser only ever talks to this dev server, the session cookie is
// same-origin (no CORS / third-party cookie issues), including behind GitHub
// Codespaces port forwarding. Codespaces serves the forwarded port under
// *.app.github.dev, so allow that host when running inside a codespace (the
// __VITE_ADDITIONAL_SERVER_ALLOWED_HOSTS env var works too).
const allowedHosts = process.env.CODESPACES === "true" ? [".app.github.dev"] : undefined;

export default defineConfig({
  plugins: [react(), tailwindcss()],
  build: { chunkSizeWarningLimit: 1000 },
  server: {
    port: 5173,
    host: true,
    allowedHosts,
    proxy: {
      // ws: the remote-session viewer socket (/api/remote/*) is proxied too.
      "/api": { target: process.env.VITE_API_PROXY ?? "http://127.0.0.1:8000", changeOrigin: true, xfwd: true, ws: true },
    },
  },
});
