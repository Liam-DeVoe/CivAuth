import { redirect } from "react-router";

import { AppForm, AppSecretPage } from "../../components/apps";
import { redirectUris, regenerateSecret, requireAppsSession, updateApp } from "../../.server/apps";
import { notFound, readForm } from "../../.server/http";
import { store } from "../../.server/services";
import { checkCsrf } from "../../.server/session";
import type { SessionRow } from "../../.server/store";
import type { Route } from "./+types/edit";

function ownedApp(clientId: string, session: SessionRow) {
  const row = store.app(clientId);
  if (row === null || row.owner_uuid !== session.uuid) throw notFound();
  return row;
}

export function loader({ request, params }: Route.LoaderArgs) {
  const session = requireAppsSession(request);
  const row = ownedApp(params.client_id, session);
  return {
    csrf: session.csrf,
    app: { clientId: row.client_id, name: row.name },
    fields: { name: row.name, redirectUris: redirectUris(row) },
  };
}

export async function action({ request, params }: Route.ActionArgs) {
  const session = requireAppsSession(request);
  const row = ownedApp(params.client_id, session);
  const form = await readForm(request);
  checkCsrf(session, form);
  const intent = form.get("intent");
  if (intent === "regenerate") return regenerateSecret(row);
  if (intent === "delete") {
    store.deleteApp(row.client_id);
    return redirect("/apps");
  }
  return updateApp(row, form);
}

export default function EditApp({ loaderData, actionData }: Route.ComponentProps) {
  if (actionData?.secret) return <AppSecretPage {...actionData.secret} />;
  return (
    <AppForm
      app={loaderData.app}
      csrf={loaderData.csrf}
      fields={actionData?.fields ?? loaderData.fields}
      errors={actionData?.errors ?? []}
      message={actionData?.message}
    />
  );
}
