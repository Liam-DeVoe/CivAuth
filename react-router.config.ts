import type { Config } from "@react-router/dev/config";

import { configPath, issuerPathOf } from "./app/.server/config";

export default {
  ssr: true,
  basename: `${issuerPathOf(configPath())}/`,
  routeDiscovery: { mode: "initial" },
  future: {
    v8_middleware: true,
    v8_trailingSlashAwareDataRequests: true,
  },
} satisfies Config;
