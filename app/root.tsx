import type { ReactNode } from "react";
import { Links, Outlet, Scripts, ScrollRestoration } from "react-router";

import type { Route } from "./+types/root";
import { useNonce } from "./components/document";
import { ThemePrepaint } from "./components/theme";
import { isCrossSite } from "./.server/security";
import { config } from "./.server/services";
import { getSession } from "./.server/session";
import stylesheet from "./styles/style.scss?url";

export { ErrorBoundary } from "./components/error-page";

export const links: Route.LinksFunction = () => [
  { rel: "stylesheet", href: stylesheet },
  { rel: "icon", href: `${import.meta.env.BASE_URL}static/icon.svg`, type: "image/svg+xml" },
];

const CROSS_SITE_ENDPOINTS = ["/oauth/token", "/join/issue"];

export const middleware: Route.MiddlewareFunction[] = [
  ({ request }, next) => {
    if (request.method === "GET" || request.method === "HEAD") return next();
    const path = new URL(request.url).pathname;
    const crossSiteAllowed = CROSS_SITE_ENDPOINTS.some((endpoint) => path === config.path(endpoint));
    if (!crossSiteAllowed && isCrossSite(request)) {
      throw new Response("This form could not be verified", { status: 400 });
    }
    return next();
  },
];

export function loader({ request }: Route.LoaderArgs) {
  const session = getSession(request);
  return {
    account: session && { uuid: session.uuid, name: session.name, csrf: session.csrf },
  };
}

export function Layout({ children }: { children: ReactNode }) {
  const nonce = useNonce();
  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        <meta charSet="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <meta name="robots" content="noindex" />
        <meta name="color-scheme" content="light dark" />
        <ThemePrepaint />
        <Links nonce="" />
      </head>
      <body>
        {children}
        <ScrollRestoration nonce={nonce} />
        <Scripts nonce={nonce} />
      </body>
    </html>
  );
}

export default function App() {
  return <Outlet />;
}
