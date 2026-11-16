import { useEffect, useRef } from "react";
import { Form } from "react-router";

import { Notice } from "../../components/ui";
import { AddPasskey } from "../../components/passkeys";
import { accountAction, accountPage } from "../../.server/account";
import { readForm } from "../../.server/http";
import { checkCsrf, requireSession } from "../../.server/session";
import type { Route } from "./+types/index";

export function loader({ request }: Route.LoaderArgs) {
  return accountPage(requireSession(request, "/account"));
}

export async function action({ request }: Route.ActionArgs) {
  const session = requireSession(request, "/account");
  const form = await readForm(request);
  checkCsrf(session, form);
  return accountAction(request, session, form);
}

export default function Account({ loaderData: page, actionData }: Route.ComponentProps) {
  const password = useRef<HTMLFormElement>(null);
  const changePassword = useRef<HTMLDetailsElement>(null);
  useEffect(() => {
    if (!actionData?.message) return;
    password.current?.reset();
    if (changePassword.current) changePassword.current.open = false;
  }, [actionData]);
  return (
    <div className="page-account">
      <title>Your account - CivAuth</title>
      <div className="title">Your account</div>
      {actionData?.message ? <Notice>{actionData.message}</Notice> : null}
      {actionData?.error ? <div className="text text--error">{actionData.error}</div> : null}
      <table className="grid">
        <tbody>
          <tr>
            <th>Minecraft name</th>
            <td>{page.name}</td>
          </tr>
          <tr>
            <th>Minecraft UUID</th>
            <td>
              <span className="code">{page.uuid}</span>
            </td>
          </tr>
        </tbody>
      </table>
      <div className="heading section-title">Password</div>
      {page.hasPassword ? (
        <details className="reveal" ref={changePassword} open={actionData?.error ? true : undefined}>
          <summary className="button button--danger reveal__toggle">Change password</summary>
          <Form method="post" ref={password}>
            <input type="hidden" name="intent" value="password" />
            <input type="hidden" name="csrf" value={page.csrf} />
            <label className="field" htmlFor="new">
              New password
            </label>
            <input className="field__input" type="password" id="new" name="new" required />
            <div className="actions">
              <button type="submit" className="button">
                Save new password
              </button>
            </div>
          </Form>
        </details>
      ) : (
        <Form method="post" ref={password}>
          <input type="hidden" name="intent" value="password" />
          <input type="hidden" name="csrf" value={page.csrf} />
          <label className="field" htmlFor="new">
            Password
          </label>
          <input className="field__input" type="password" id="new" name="new" autoComplete="new-password" required />
          <div className="actions">
            <button type="submit" className="button">
              Set a password
            </button>
          </div>
        </Form>
      )}
      <div className="heading section-title">Passkeys</div>
      {page.passkeys.length > 0 ? (
        <table>
          <tbody>
            <tr>
              <th>Added</th>
              <th></th>
            </tr>
            {page.passkeys.map((passkey) => (
              <tr key={passkey.credentialId}>
                <td>{passkey.added}</td>
                <td>
                  <Form method="post">
                    <input type="hidden" name="intent" value="delete-passkey" />
                    <input type="hidden" name="csrf" value={page.csrf} />
                    <input type="hidden" name="credential_id" value={passkey.credentialId} />
                    <button type="submit" className="button button--small button--danger">
                      Remove
                    </button>
                  </Form>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : (
        <div className="text">No passkeys yet.</div>
      )}
      <AddPasskey csrf={page.csrf} serverError={actionData?.passkeyError} />
      <div className="heading section-title">Authorized apps</div>
      {page.grants.length > 0 ? (
        <table>
          <tbody>
            <tr>
              <th>App</th>
              <th>Owner</th>
              <th>Last used</th>
              <th></th>
            </tr>
            {page.grants.map((grant) => (
              <tr key={grant.clientId}>
                <td>{grant.name}</td>
                <td>{grant.owner ?? "None"}</td>
                <td>{grant.used}</td>
                <td>
                  <Form method="post">
                    <input type="hidden" name="intent" value="remove-app" />
                    <input type="hidden" name="csrf" value={page.csrf} />
                    <input type="hidden" name="client_id" value={grant.clientId} />
                    <button type="submit" className="button button--small button--danger">
                      Remove
                    </button>
                  </Form>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : (
        <div className="text">You have not authorized any apps yet.</div>
      )}
    </div>
  );
}
