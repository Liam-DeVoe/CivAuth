import { fileURLToPath } from "node:url";

import express from "express";

const DEV = process.env.NODE_ENV !== "production";
const HOST = process.env.HOST || "127.0.0.1";
const PORT = Number.parseInt(process.env.PORT || "3000", 10);

const server = express();
server.disable("x-powered-by");

if (DEV) {
  const vite = await import("vite").then((vite) =>
    vite.createServer({ server: { middlewareMode: true } }),
  );
  const { config } = await vite.ssrLoadModule("./server/app.ts");
  server.set("trust proxy", config.trustProxy);
  server.use(vite.middlewares);
  server.use(async (req, res, next) => {
    try {
      const { app } = await vite.ssrLoadModule("./server/app.ts");
      app(req, res, next);
    } catch (error) {
      next(error);
    }
  });
} else {
  const { app, checkBuild, config, SECURITY_HEADERS, STATIC_FILE_CSP } = await import("./build/server/index.js");
  await checkBuild();
  server.set("trust proxy", config.trustProxy);
  const client = fileURLToPath(new URL("./build/client", import.meta.url));
  const setHeaders = (res) => {
    for (const [name, value] of SECURITY_HEADERS) res.setHeader(name, value);
    res.setHeader("Content-Security-Policy", STATIC_FILE_CSP);
  };
  const options = { index: false, redirect: false, setHeaders };
  server.use(
    `${config.issuerPath}/assets`,
    express.static(`${client}/assets`, { ...options, immutable: true, maxAge: "1y" }),
  );
  server.use(config.issuerPath || "/", express.static(client, options));
  server.use(app);
}

server.listen(PORT, HOST, () => {
  console.log(`CivAuth listening on http://${HOST}:${PORT}`);
});
