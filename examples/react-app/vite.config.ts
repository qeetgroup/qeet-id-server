import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

export default defineConfig({
  plugins: [react()],
  // SPA fallback (the default) serves index.html for /login, /callback, /logout.
  server: { port: 3020 },
  preview: { port: 3020 },
});
