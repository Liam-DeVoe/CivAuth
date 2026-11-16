import { loginOptions } from "../../.server/passkey";
import type { Route } from "./+types/passkey-options";

export function action({ request }: Route.ActionArgs) {
  return loginOptions(request);
}
