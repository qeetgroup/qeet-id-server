import { fileURLToPath, URL } from "node:url";
import { defineConfig } from "vitest/config";

/** Keep unit tests independent from TanStack Start/Nitro application plugins. */
export default defineConfig({
  resolve: {
    alias: {
      "@": fileURLToPath(new URL("./src", import.meta.url)),
    },
  },
  test: {
    environment: "node",
    passWithNoTests: true,
  },
});
