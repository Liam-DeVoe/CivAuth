import { avatarPng, pngResponse, UUID } from "../.server/avatar";
import type { Route } from "./+types/avatar";

export async function loader({ request, params }: Route.LoaderArgs) {
  if (!UUID.test(params.uuid)) return new Response("Not Found", { status: 404 });
  return pngResponse(await avatarPng(params.uuid), request.headers.get("If-None-Match"));
}
