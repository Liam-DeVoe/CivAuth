import { reactRouter } from "@react-router/dev/vite";
import { defineConfig } from "vite";

import { configPath, issuerPathOf } from "./app/.server/config";

const issuerPath = issuerPathOf(configPath());

export default defineConfig(({ isSsrBuild }) => ({
  base: `${issuerPath}/`,
  build: isSsrBuild ? { rollupOptions: { input: "./server/app.ts" } } : {},
  server: {
    fs: {
      deny: [".env", ".env.*", "*.{crt,pem}", "config*.json", "*.sqlite*", ".git/**"],
    },
  },
  css: {
    preprocessorOptions: {
      scss: { silenceDeprecations: ["import"] },
    },
  },
  plugins: [reactRouter()],
}));
