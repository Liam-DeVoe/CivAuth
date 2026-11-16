import type { ReactNode } from "react";
import { Form, Link, useHref, useRouteLoaderData } from "react-router";

import type { loader as rootLoader } from "../root";
import { ThemeToggle } from "./theme";
import { Dropdown } from "./ui";

export function Page({ footer, children }: { footer?: ReactNode; children: ReactNode }) {
  return (
    <>
      <Topbar />
      <div className="page">{children}</div>
      <Footer>{footer}</Footer>
    </>
  );
}

export function Footer({ children }: { children?: ReactNode }) {
  return (
    <div className="footer">
      <Link className="footer__link" to="/docs">
        Docs
      </Link>
      {children}
    </div>
  );
}

export function useAccount() {
  return useRouteLoaderData<typeof rootLoader>("root")?.account ?? null;
}

export function Avatar({ uuid, size, className }: { uuid: string; size: number; className: string }) {
  const src = useHref(`/avatar/${uuid}.png`);
  return <img className={className} src={src} width={size} height={size} alt="" />;
}

function Topbar() {
  const account = useAccount();
  return (
    <div className="topbar">
      <ThemeToggle />
      {account ? (
        <Dropdown className="menu">
          <summary className="menu__toggle">
            <Avatar className="menu__avatar" uuid={account.uuid} size={28} />
            <span className="menu__name">{account.name}</span>
            <svg className="menu__caret" viewBox="0 0 10 10" aria-hidden="true">
              <path d="M1 3l4 4 4-4z" />
            </svg>
          </summary>
          <div className="menu__list">
            <Link className="menu__item" to="/account">
              Account
            </Link>
            <Link className="menu__item" to="/apps">
              OAuth apps
            </Link>
            <Form method="post" action="/signout">
              <input type="hidden" name="csrf" value={account.csrf} />
              <button type="submit" className="menu__item">
                Sign out
              </button>
            </Form>
          </div>
        </Dropdown>
      ) : null}
    </div>
  );
}
