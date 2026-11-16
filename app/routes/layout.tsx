import type { ReactNode } from "react";
import { Outlet, useMatches } from "react-router";

import { Page } from "../components/layout";

export { ErrorBoundary } from "../components/error-page";

export interface PageHandle {
  footer?: ReactNode;
}

export default function PageLayout() {
  const handle = useMatches().at(-1)?.handle as PageHandle | undefined;
  return (
    <Page footer={handle?.footer}>
      <Outlet />
    </Page>
  );
}
