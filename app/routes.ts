import { layout, route, type RouteConfig } from "@react-router/dev/routes";

export default [
  layout("routes/layout.tsx", [
    route("/", "routes/login.tsx"),
    route("login/minecraft", "routes/login/minecraft.tsx"),
    route("callback", "routes/callback.tsx"),
    route("account", "routes/account/index.tsx"),
    route("apps", "routes/apps/index.tsx"),
    route("apps/new", "routes/apps/new.tsx"),
    route("apps/:client_id", "routes/apps/edit.tsx"),
    route("docs", "routes/docs.tsx"),
    route("permissions", "routes/permissions.tsx"),
    route("*", "routes/not-found.tsx"),
  ]),
  route("oauth/authorize", "routes/oauth/authorize.tsx"),
  route("avatar/:uuid.png", "routes/avatar.ts"),
  route("oauth/token", "routes/oauth/token.ts"),
  route("oauth/user", "routes/oauth/user.ts"),
  route("join/issue", "routes/join/issue.ts"),
  route("signout", "routes/signout.ts"),
  route("login/passkey/options", "routes/login/passkey-options.ts"),
  route("account/passkey/options", "routes/account/passkey-options.ts"),
] satisfies RouteConfig;
