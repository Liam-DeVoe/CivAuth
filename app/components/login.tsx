import { useEffect, useRef, type ReactNode, type RefObject } from "react";
import { Form, Link } from "react-router";

import type { AppSummary, LoginErrors } from "../.server/login";
import { Avatar } from "./layout";
import { OtpDigits, useCodeEntry } from "./otp";
import { usePasskeyLogin } from "./passkeys";
import { CopyButton, Dialog, Dropdown, Warning } from "./ui";

function Address({ address }: { address: string }) {
  return (
    <div className="input-row input-row--address">
      <span className="secret input-row__value">{address}</span>
      <CopyButton value={address} />
    </div>
  );
}

function PasswordForm({
  errors,
  focusRef,
  children,
}: {
  errors: LoginErrors | null;
  focusRef?: RefObject<HTMLInputElement | null>;
  children?: ReactNode;
}) {
  const passkey = usePasskeyLogin(errors);
  const form = useRef<HTMLFormElement>(null);
  useEffect(() => form.current?.reset(), [errors]);
  const error = errors?.error;
  const passkeyError = passkey.error ?? errors?.passkeyError;
  return (
    <Form method="post" ref={form}>
      <input type="hidden" name="intent" value="password" />
      {children}
      <label className="field" htmlFor="username">
        Minecraft username
      </label>
      <input
        className="field__input"
        type="text"
        id="username"
        name="username"
        defaultValue={errors?.username ?? ""}
        maxLength={16}
        autoCapitalize="off"
        autoCorrect="off"
        spellCheck="false"
        autoComplete="username webauthn"
        required
        ref={error ? undefined : focusRef}
      />
      <label className="field" htmlFor="password">
        CivAuth password
      </label>
      <input
        className="field__input"
        type="password"
        id="password"
        name="password"
        autoComplete="current-password"
        required
        ref={error ? focusRef : undefined}
      />
      {error ? <div className="text text--error">{error}</div> : null}
      {passkeyError ? <div className="text text--error">{passkeyError}</div> : null}
      <div className="actions">
        <button type="submit" className="button">
          Log in
        </button>
      </div>
      <button type="button" className="button button--quiet" onClick={passkey.start}>
        Log in with passkey
      </button>
    </Form>
  );
}

export function LoginPage({ address, errors }: { address: string; errors: LoginErrors | null }) {
  const entry = useCodeEntry();
  useEffect(() => {
    if (errors?.joinError) entry.clear();
  }, [errors]);
  return (
    <>
      <title>Log in - CivAuth</title>
      <div className="title">Log in</div>
      <div className="split">
        <div className="split__half">
          <div className="split__title">New or existing account</div>
          <div className="text">Join CivAuth&apos;s Minecraft server to receive a verification code.</div>
          <Address address={address} />
          <Form method="post" ref={entry.form}>
            <input type="hidden" name="intent" value="code" />
            <input type="hidden" name="code" value={entry.code} />
            <div className="field">Verification code</div>
            <OtpDigits entry={entry} />
            {errors?.joinError ? <div className="text text--error">{errors.joinError}</div> : null}
            <div className="actions">
              <button type="submit" className="button">
                Log in
              </button>
            </div>
          </Form>
        </div>
        <div className="split__half">
          <div className="split__title">Existing account</div>
          <PasswordForm errors={errors} />
        </div>
      </div>
    </>
  );
}

export function LoginCard({ app, address, errors }: { app: AppSummary; address: string; errors: LoginErrors | null }) {
  const entry = useCodeEntry();
  useEffect(() => {
    if (errors?.joinError) entry.clear();
  }, [errors]);
  const existing = useRef<HTMLDialogElement>(null);
  const field = useRef<HTMLInputElement>(null);
  const open = () => {
    if (!existing.current?.open) existing.current?.showModal();
    field.current?.focus();
  };
  useEffect(() => {
    if (errors?.error || errors?.passkeyError) open();
  }, [errors]);

  return (
    <>
      <title>{`Log in to ${app.name} - CivAuth`}</title>
      <AppRequest app={app} />
      <div className="consent__methods">
        <Form method="post" ref={entry.form}>
          <input type="hidden" name="intent" value="code" />
          <input type="hidden" name="code" value={entry.code} />
          <div className="consent__title">Verify your Minecraft account</div>
          <ol className="steps">
            <li className="steps__item">
              Join the Minecraft server
              <Address address={address} />
            </li>
            <li className="steps__item">
              Enter your verification code
              <OtpDigits entry={entry} />
            </li>
          </ol>
          {errors?.joinError ? <div className="text text--error">{errors.joinError}</div> : null}
          <div className="actions">
            <button type="submit" className="button button--fill">
              Log in
            </button>
          </div>
          <div className="consent__alt">
            Already have a CivAuth account?{" "}
            <button type="button" className="button button--quiet" onClick={open}>
              Log in with password or passkey
            </button>
          </div>
        </Form>
        <Dialog className="dialog" ref={existing}>
          <PasswordForm errors={errors} focusRef={field}>
            <div className="dialog__head">
              <div className="dialog__title">Log in to your CivAuth account</div>
              <button
                type="button"
                className="dialog__close"
                aria-label="Close"
                onClick={() => existing.current?.close()}
              >
                <svg viewBox="0 0 10 10" aria-hidden="true">
                  <path d="M1 1l8 8M9 1 1 9" />
                </svg>
              </button>
            </div>
          </PasswordForm>
        </Dialog>
      </div>
      <div className="consent__foot">
        <Form method="post">
          <input type="hidden" name="intent" value="cancel" />
          <button type="submit" className="button button--danger">
            Cancel
          </button>
        </Form>
        <Brand />
      </div>
    </>
  );
}

export function Consent({
  app,
  account,
  csrf,
}: {
  app: AppSummary;
  account: { uuid: string; name: string };
  csrf: string;
}) {
  return (
    <>
      <title>{`Authorize ${app.name} - CivAuth`}</title>
      <AppRequest app={app} />
      <Form method="post">
        <input type="hidden" name="intent" value="consent" />
        <input type="hidden" name="csrf" value={csrf} />
        <div className="consent__who">
          <div className="consent__person">
            <Avatar className="consent__avatar" uuid={account.uuid} size={32} />
            <span className="strong">{account.name}</span>
          </div>
          <button type="submit" name="decision" value="switch" className="button button--quiet">
            Not you?
          </button>
        </div>
        <div className="consent__foot">
          <button type="submit" name="decision" value="allow" className="button">
            Authorize
          </button>
          <button type="submit" name="decision" value="deny" className="button button--danger">
            Cancel
          </button>
          <Brand />
        </div>
      </Form>
    </>
  );
}

function AppRequest({ app }: { app: AppSummary }) {
  return (
    <>
      <div className="consent__head">
        <div className="consent__kicker">Authorization request</div>
        <div className="consent__app">{app.name}</div>
        <div className="consent__by">An app by {app.owner}</div>
      </div>
      <div className="consent__body">
        <div className="text">wants to sign you in with your CivAuth account.</div>
        <div className="text">This application will be able to:</div>
        <ul className="consent__grants">
          <li className="consent__grant">
            <svg viewBox="0 0 20 20" aria-hidden="true">
              <path d="M7 14.2 2.8 10l1.4-1.4L7 11.4l8.8-8.8 1.4 1.4z" />
            </svg>
            See your Minecraft username and UUID
          </li>
        </ul>
      </div>
    </>
  );
}

function Brand() {
  return (
    <span className="consent__brand">
      <img src={`${import.meta.env.BASE_URL}static/icon.svg`} width="18" height="18" alt="" />
      CivAuth
    </span>
  );
}

export function AlternativeLogin({ newTab = false }: { newTab?: boolean }) {
  const target = newTab ? { target: "_blank", rel: "noopener" } : {};
  return (
    <>
      <Dropdown className="footer__more">
        <summary className="footer__toggle">Alternative login methods</summary>
        <div className="dropdown__panel">
          <div className="dropdown__title">Alternative login methods</div>
          <div className="text">Log in with your Minecraft account through the web.</div>
          <Warning>
            Logging in with Minecraft gives CivAuth certain temporary permissions on your account.{" "}
            <Link to="/permissions" {...target}>
              Read more about the different authentication methods.
            </Link>
          </Warning>
          <div className="actions">
            <Link className="button" to="/login/minecraft">
              Log in with Minecraft
            </Link>
          </div>
        </div>
      </Dropdown>
      <span className="footer__sep" aria-hidden="true">
        ·
      </span>
    </>
  );
}
