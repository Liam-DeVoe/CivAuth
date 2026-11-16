export function contentSecurityPolicy(nonce: string, scripts: string, dev = false): string {
  return [
    "default-src 'none'",
    `script-src 'nonce-${nonce}' ${scripts}`,
    dev ? "style-src 'self' 'unsafe-inline'" : "style-src 'self'",
    "img-src 'self'",
    dev ? "connect-src 'self' ws: wss:" : "connect-src 'self'",
    "base-uri 'none'",
    "frame-ancestors 'none'",
    "require-trusted-types-for 'script'",
    "trusted-types 'none'",
  ].join("; ");
}

export const STATIC_FILE_CSP = "default-src 'none'; base-uri 'none'; frame-ancestors 'none'";

export const SECURITY_HEADERS: readonly [string, string][] = [
  ["X-Content-Type-Options", "nosniff"],
  ["X-Frame-Options", "DENY"],
  ["Referrer-Policy", "same-origin"],
  ["Strict-Transport-Security", "max-age=31536000"],
];

export function isCrossSite(request: Request): boolean {
  const site = request.headers.get("Sec-Fetch-Site");
  if (site !== null) return site === "cross-site" || site === "same-site";
  const origin = request.headers.get("Origin");
  return origin !== null && origin !== new URL(request.url).origin;
}
