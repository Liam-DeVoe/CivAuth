import { useEffect, useRef, useState } from "react";
import { Form, Link } from "react-router";

import type { AppSecret, Fields } from "../.server/apps";
import { MAX_NAME, MAX_URIS } from "../constants";
import { Confirm, CopyButton, Notice, useConfirmation } from "./ui";

export function AppForm({
  app,
  csrf,
  fields,
  errors,
  message,
}: {
  app: { clientId: string; name: string } | null;
  csrf: string;
  fields: Fields;
  errors: string[];
  message?: string;
}) {
  const title = app ? `Edit ${app.name}` : "Create an app";
  const regenerate = useConfirmation();
  const remove = useConfirmation();
  return (
    <>
      <title>{`${title} - CivAuth`}</title>
      <div className="title">{title}</div>
      {message ? <Notice>{message}</Notice> : null}
      {errors.map((error, index) => (
        <div className="text text--error" key={index}>
          {error}
        </div>
      ))}
      <Form method="post">
        <input type="hidden" name="csrf" value={csrf} />
        {app ? (
          <label className="field">
            Client id
            <input className="field__input" type="text" defaultValue={app.clientId} readOnly />
          </label>
        ) : null}
        <label className="field">
          Name
          <input
            className="field__input"
            type="text"
            name="name"
            defaultValue={fields.name}
            maxLength={MAX_NAME}
            required
          />
        </label>
        <label className="field">Redirect URIs</label>
        <RedirectUris initial={fields.redirectUris} />
        <div className="actions">
          <button type="submit" className="button">
            {app ? "Save" : "Register"}
          </button>
          <Link className="button button--plain" to="/apps">
            Cancel
          </Link>
        </div>
      </Form>
      {app ? (
        <>
          <div className="heading section-title">Manage</div>
          <div className="actions">
            <Form method="post" {...regenerate.form}>
              <input type="hidden" name="intent" value="regenerate" />
              <input type="hidden" name="csrf" value={csrf} />
              <button type="submit" className="button button--danger">
                Regenerate secret
              </button>
            </Form>
            <Form method="post" {...remove.form}>
              <input type="hidden" name="intent" value="delete" />
              <input type="hidden" name="csrf" value={csrf} />
              <button type="submit" className="button button--danger">
                Delete app
              </button>
            </Form>
          </div>
          <Confirm
            confirmation={regenerate}
            title="Regenerate secret?"
            body="This will revoke the current secret and create a new one."
            action="Regenerate secret"
          />
          <Confirm
            confirmation={remove}
            title={`Delete ${app.name}?`}
            body="This cannot be undone."
            action="Delete app"
          />
        </>
      ) : null}
    </>
  );
}

export function AppSecretPage({ clientId, name, secret }: AppSecret) {
  return (
    <>
      <title>{`${name} - CivAuth`}</title>
      <div className="title">{name}</div>
      <div className="credentials">
        <label className="credentials__label" htmlFor="client-id">
          Client id:
        </label>
        <input
          className="credentials__input"
          id="client-id"
          defaultValue={clientId}
          readOnly
          onFocus={(event) => event.currentTarget.select()}
        />
        <CopyButton value={clientId} />
        <label className="credentials__label" htmlFor="client-secret">
          Client secret:
        </label>
        <input
          className="credentials__input"
          id="client-secret"
          defaultValue={secret}
          readOnly
          onFocus={(event) => event.currentTarget.select()}
        />
        <CopyButton value={secret} />
      </div>
      <div className="text">Copy the client secret now. It will not be shown later.</div>
      <div className="text">
        See <Link to="/docs">the developer docs</Link> for details on setting up your app.
      </div>
      <div className="actions">
        <Link className="button" to="/apps">
          OAuth apps
        </Link>
      </div>
    </>
  );
}

function RedirectUris({ initial }: { initial: string[] }) {
  const [rows, setRows] = useState(() => initial.map((value, key) => ({ key, value })));
  const nextKey = useRef(initial.length);
  const inputs = useRef(new Map<number, HTMLInputElement>());
  const [focus, setFocus] = useState<number | null>(null);
  useEffect(() => {
    if (focus !== null) inputs.current.get(focus)?.focus();
  }, [focus]);

  function add() {
    if (rows.length >= MAX_URIS) return;
    const key = nextKey.current++;
    setRows([...rows, { key, value: "" }]);
    setFocus(key);
  }

  function remove(key: number) {
    if (rows.length === 1) setRows([{ ...rows[0]!, value: "" }]);
    else setRows(rows.filter((row) => row.key !== key));
  }

  function edit(key: number, value: string) {
    setRows(rows.map((row) => (row.key === key ? { key, value } : row)));
  }

  return (
    <>
      <div>
        {rows.map((row) => (
          <div className="input-row" key={row.key}>
            <input
              className="input-row__input"
              type="text"
              name="redirect_uris[]"
              value={row.value}
              onChange={(event) => edit(row.key, event.currentTarget.value)}
              ref={(element) => {
                if (element) inputs.current.set(row.key, element);
                else inputs.current.delete(row.key);
              }}
            />
            <button type="button" className="button button--plain button--small" onClick={() => remove(row.key)}>
              Remove
            </button>
          </div>
        ))}
      </div>
      <button
        type="button"
        className="button button--plain button--small"
        hidden={rows.length >= MAX_URIS}
        onClick={add}
      >
        Add
      </button>
    </>
  );
}
