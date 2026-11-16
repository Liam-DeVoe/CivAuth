import { isRouteErrorResponse, Link, useRouteError } from "react-router";

import type { ErrorAction, ErrorPageData } from "../.server/http";
import { Page } from "./layout";

export function ErrorBoundary() {
  return (
    <Page>
      <RouteError />
    </Page>
  );
}

function RouteError() {
  const error = useRouteError();
  if (isRouteErrorResponse(error)) {
    if (isErrorPageData(error.data)) {
      const { title, message, actions } = error.data;
      return <ErrorPage title={title} message={message} actions={actions} />;
    }
    if (error.status === 404) return <ErrorPage title="Not found" />;
    if (error.status === 405) return <ErrorPage title="Method not allowed" />;
    if (typeof error.data === "string" && error.data) return <ErrorPage title={error.data} />;
    return <ErrorPage title={error.statusText || "Error"} />;
  }
  return (
    <ErrorPage
      title="Internal Server Error"
      message="The server encountered an internal error and was unable to complete your request."
    />
  );
}

function isErrorPageData(value: unknown): value is ErrorPageData {
  return typeof value === "object" && value !== null && typeof (value as ErrorPageData).title === "string";
}

function ErrorPage({ title, message, actions = [] }: { title: string; message?: string; actions?: ErrorAction[] }) {
  return (
    <>
      <title>{`${title} - CivAuth`}</title>
      <div className="title">{title}</div>
      {message ? <div className="text text--error">{message}</div> : null}
      {actions.length > 0 ? (
        <div className="actions">
          {actions.map((action) => {
            const className = action.plain ? "button button--plain" : "button";
            const key = action.href + action.label;
            return URL.canParse(action.href) ? (
              <a key={key} className={className} href={action.href}>
                {action.label}
              </a>
            ) : (
              <Link key={key} className={className} to={action.href}>
                {action.label}
              </Link>
            );
          })}
        </div>
      ) : null}
    </>
  );
}
