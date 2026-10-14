import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

// In dev, /api is proxied to the FastAPI backend (override with VITE_API_PROXY).
export default defineConfig({
  plugins: [react(), tailwindcss()],
  build: { chunkSizeWarningLimit: 1000 },
  server: {
    port: 5173,
    host: true,
    proxy: {
      "/api": { target: process.env.VITE_API_PROXY ?? "http://127.0.0.1:8000", changeOrigin: true },
    },
  },
});
