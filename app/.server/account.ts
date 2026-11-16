import { formString, unverifiedForm } from "./http";
import { addPasskey } from "./passkey";
import { generatePasswordHash } from "./password";
import { store } from "./services";
import { now } from "./session";
import type { SessionRow } from "./store";

export interface AccountActionData {
  message?: string;
  error?: string;
  passkeyError?: string;
}

export function accountPage(session: SessionRow) {
  const account = store.account(session.uuid);
  return {
    name: session.name,
    uuid: hyphenated(session.uuid),
    hasPassword: account !== null && account.password_hash !== null,
    passkeys: store.passkeysFor(session.uuid).map((row) => ({
      credentialId: row.credential_id,
      added: longDate(row.created_at),
    })),
    grants: store.grantsFor(session.uuid).map((row) => ({
      name: row.name,
      clientId: row.client_id,
      owner: row.owner_name,
      used: longDate(row.used_at),
    })),
    csrf: session.csrf,
  };
}

export async function accountAction(request: Request, session: SessionRow, form: FormData): Promise<AccountActionData> {
  const intent = formString(form, "intent");
  if (intent === "password") {
    const password = formString(form, "new");
    if (!password) return { error: "Enter a password." };
    const hadPassword = store.account(session.uuid)?.password_hash != null;
    store.setPassword(session.uuid, await generatePasswordHash(password), now());
    return { message: hadPassword ? "Password changed." : "Password set." };
  }
  if (intent === "remove-app") {
    const clientId = formString(form, "client_id") ?? "";
    const app = store.app(clientId);
    if (!store.deleteGrant(session.uuid, clientId)) return { error: "That app has already been removed." };
    return { message: `Removed ${app === null ? "That app" : app.name} from authorized apps.` };
  }
  if (intent === "delete-passkey") {
    const credentialId = formString(form, "credential_id") ?? "";
    if (!store.deletePasskey(credentialId, session.uuid)) return { error: "That passkey has already been removed." };
    return { message: "That passkey has been removed." };
  }
  if (intent === "add-passkey") {
    const error = await addPasskey(request, session, formString(form, "credential") ?? "");
    return error === null ? { message: "Passkey added." } : { passkeyError: error };
  }
  throw unverifiedForm();
}

const MONTHS = [
  "January",
  "February",
  "March",
  "April",
  "May",
  "June",
  "July",
  "August",
  "September",
  "October",
  "November",
  "December",
];

function longDate(seconds: number): string {
  const moment = new Date(seconds * 1000);
  return `${moment.getUTCDate()} ${MONTHS[moment.getUTCMonth()]} ${moment.getUTCFullYear()}`;
}

export function hyphenated(uuid: string): string {
  return [uuid.slice(0, 8), uuid.slice(8, 12), uuid.slice(12, 16), uuid.slice(16, 20), uuid.slice(20)].join("-");
}
