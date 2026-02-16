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
    global: "globalThis"
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
