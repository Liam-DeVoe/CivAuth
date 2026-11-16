import { redirectDocument } from "react-router";

import { expired } from "../../.server/http";
import { minecraft } from "../../.server/services";
import { pendingRequest } from "../../.server/session";
import type { Route } from "./+types/minecraft";

export function loader({ request }: Route.LoaderArgs) {
  const req = pendingRequest(request);
  if (req === null) throw expired();
  return redirectDocument(minecraft.loginUrl(req.id));
}

export default function LoginMinecraft() {
  return null;
}
