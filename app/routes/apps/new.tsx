import { AppForm, AppSecretPage } from "../../components/apps";
import { createApp, requireAppsSession } from "../../.server/apps";
import { readForm } from "../../.server/http";
import { checkCsrf } from "../../.server/session";
import type { Route } from "./+types/new";

export function loader({ request }: Route.LoaderArgs) {
  return { csrf: requireAppsSession(request).csrf };
}

export async function action({ request }: Route.ActionArgs) {
  const session = requireAppsSession(request);
  const form = await readForm(request);
  checkCsrf(session, form);
  return createApp(session, form);
}

export default function NewApp({ loaderData, actionData }: Route.ComponentProps) {
  if (actionData?.secret) return <AppSecretPage {...actionData.secret} />;
  return (
    <AppForm
      app={null}
      csrf={loaderData.csrf}
      fields={actionData?.fields ?? { name: "", redirectUris: [""] }}
      errors={actionData?.errors ?? []}
    />
  );
}
