import { createRequestHandler } from "@react-router/express";
import express from "express";
import { RouterContextProvider, type ServerBuild } from "react-router";

import { requestContext } from "../app/context";
import { contentSecurityPolicy, SECURITY_HEADERS } from "../app/.server/security";
import { config } from "../app/.server/services";
import { randomToken } from "../app/.server/session";

export { SECURITY_HEADERS, STATIC_FILE_CSP } from "../app/.server/security";

const DEV = process.env.NODE_ENV !== "production";
const MAX_BODY = 1024 * 1024;

export { config } from "../app/.server/services";

const scriptSource = DEV ? "'self'" : `${config.issuer}/assets/`;

async function getBuild(): Promise<ServerBuild> {
  return (await import("virtual:react-router/server-build")) as ServerBuild;
}

export async function checkBuild(): Promise<void> {
  const { basename } = await getBuild();
  if (basename !== `${config.issuerPath}/`) {
    throw new Error(
      `the build is for the issuer path ${basename} but the config's is ${config.issuerPath}/;` +
        " rebuild with this config file",
    );
  }
}

export const app = express.Router();

app.use((_req, res, next) => {
  const nonce = randomToken();
  res.locals.nonce = nonce;
  for (const [name, value] of SECURITY_HEADERS) res.setHeader(name, value);
  res.setHeader("Content-Security-Policy", contentSecurityPolicy(nonce, scriptSource, DEV));
  next();
});

const METHODS = new Set(["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]);

app.use((req, res, next) => {
  if (!METHODS.has(req.method)) {
    res.status(405).type("text").send("Method Not Allowed");
    return;
  }
  if (req.method === "GET" || req.method === "HEAD") return next();
  const length = req.get("Content-Length");
  if (length === undefined && req.get("Transfer-Encoding") !== undefined) {
    res.status(411).type("text").send("Length Required");
  } else if (Number(length) > MAX_BODY) {
    res.status(413).type("text").send("Content Too Large");
  } else {
    next();
  }
});

app.use((req, res, next) => {
  const [path, query] = req.originalUrl.split(/(?=\?)/);
  if (config.issuerPath && path === config.issuerPath) res.redirect(308, `${config.issuerPath}/${query ?? ""}`);
  else next();
});

app.use(
  createRequestHandler({
    build: getBuild,
    getLoadContext(req, res) {
      const context = new RouterContextProvider();
      context.set(requestContext, { nonce: res.locals.nonce as string, remoteAddress: req.ip ?? "" });
      return context;
    },
  }),
);
