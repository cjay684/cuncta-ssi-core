import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { nodePolyfills } from "vite-plugin-node-polyfills";

export default defineConfig({
  plugins: [
    react(),
    nodePolyfills({
      include: ["buffer", "process", "crypto", "stream"],
      protocolImports: true
    })
  ],
  define: {
    global: "globalThis",
    // Customer builds must not include CI-only fallback code paths.
    __CI_TEST_BUILD__: false
  },
  resolve: {
    alias: {
      buffer: "buffer/"
    }
  },
  server: {
    port: 5173
  }
});
