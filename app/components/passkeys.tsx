import {
  browserSupportsWebAuthn,
  browserSupportsWebAuthnAutofill,
  startAuthentication,
  startRegistration,
  WebAuthnAbortService,
  WebAuthnError,
  type PublicKeyCredentialCreationOptionsJSON,
  type PublicKeyCredentialRequestOptionsJSON,
} from "@simplewebauthn/browser";
import { useEffect, useState } from "react";
import { useHref, useSubmit } from "react-router";

const UNREADABLE = "The server sent something unexpected. Try again.";

async function fetchOptions<T>(href: string, body: unknown): Promise<T> {
  const response = await fetch(href, {
    method: "POST",
    credentials: "same-origin",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  let result: T & { error?: string };
  try {
    result = await response.json();
  } catch {
    throw new Error(UNREADABLE);
  }
  if (result.error) throw new Error(result.error);
  return result;
}

function isCeremonyError(reason: unknown): boolean {
  return reason instanceof WebAuthnError || reason instanceof DOMException;
}

function messageOf(reason: unknown): string {
  const error = reason instanceof WebAuthnError && reason.cause instanceof Error ? reason.cause : reason;
  return error instanceof Error ? error.message : "";
}

export function usePasskeyLogin(attempt: unknown): { error: string | null; start: () => void } {
  const [error, setError] = useState<string | null>(null);
  const submit = useSubmit();
  const optionsHref = useHref("/login/passkey/options");

  async function signIn(autofill: boolean, active: () => boolean) {
    const optionsJSON = await fetchOptions<PublicKeyCredentialRequestOptionsJSON>(optionsHref, {});
    if (!active()) return;
    const credential = await startAuthentication({ optionsJSON, useBrowserAutofill: autofill });
    if (!active()) return;
    await submit({ intent: "passkey", credential: JSON.stringify(credential) }, { method: "post" });
  }

  useEffect(() => {
    if (!browserSupportsWebAuthn()) return;
    let active = true;
    browserSupportsWebAuthnAutofill()
      .then((available) => (available && active ? signIn(true, () => active) : undefined))
      .catch(() => {});
    return () => {
      active = false;
      WebAuthnAbortService.cancelCeremony();
    };
  }, [attempt]);

  function start() {
    if (!browserSupportsWebAuthn()) return;
    setError(null);
    signIn(false, () => true).catch((reason: unknown) => {
      if (isCeremonyError(reason)) return;
      setError(messageOf(reason) || "Invalid passkey.");
    });
  }

  return { error, start };
}

export function AddPasskey({ csrf, serverError }: { csrf: string; serverError?: string }) {
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const submit = useSubmit();
  const optionsHref = useHref("/account/passkey/options");

  useEffect(() => {
    if (!browserSupportsWebAuthn()) setError("This browser cannot use passkeys.");
  }, []);

  async function add() {
    if (!browserSupportsWebAuthn()) return;
    setError(null);
    setBusy(true);
    try {
      const optionsJSON = await fetchOptions<PublicKeyCredentialCreationOptionsJSON>(optionsHref, { csrf });
      const credential = await startRegistration({ optionsJSON });
      await submit(
        { intent: "add-passkey", csrf, credential: JSON.stringify(credential) },
        { method: "post", preventScrollReset: true },
      );
    } catch (reason) {
      const name = reason instanceof Error ? reason.name : "";
      if (name === "NotAllowedError" || name === "AbortError") return;
      if (name === "InvalidStateError") setError("This device already has a passkey for your account.");
      else setError(messageOf(reason) || "Something went wrong. Try again.");
    } finally {
      setBusy(false);
    }
  }

  const shown = error ?? serverError;
  return (
    <>
      {shown ? <div className="text text--error">{shown}</div> : null}
      <div className="actions">
        <button type="button" className="button" disabled={busy} onClick={add}>
          Add a passkey
        </button>
      </div>
    </>
  );
}
