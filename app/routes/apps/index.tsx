import { Link } from "react-router";

import { requireAppsSession } from "../../.server/apps";
import { MAX_PER_OWNER } from "../../.server/constants";
import { store } from "../../.server/services";
import type { Route } from "./+types/index";

export function loader({ request }: Route.LoaderArgs) {
  const session = requireAppsSession(request);
  const rows = store.appsOwnedBy(session.uuid);
  return {
    apps: rows.map((row) => ({ name: row.name, href: "/apps/" + encodeURIComponent(row.client_id) })),
    canCreate: rows.length < MAX_PER_OWNER,
  };
}

export default function Apps({ loaderData }: Route.ComponentProps) {
  return (
    <>
      <title>OAuth apps - CivAuth</title>
      <div className="title">OAuth apps</div>
      <div className="text">
        OAuth apps let people sign into your site with their Minecraft account.{" "}
        <Link to="/docs">See the docs for details</Link>.
      </div>
      {loaderData.apps.length > 0 ? (
        <div className="cards">
          {loaderData.apps.map((app) => (
            <div className="cards__item" key={app.href}>
              <Link className="cards__link" to={app.href}>
                <span className="cards__name">{app.name}</span>
              </Link>
            </div>
          ))}
        </div>
      ) : null}
      <div className="actions">
        {loaderData.canCreate ? (
          <Link className="button" to="/apps/new">
            Create an app
          </Link>
        ) : null}
      </div>
    </>
  );
}
