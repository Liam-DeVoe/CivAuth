import { parse, serialize } from "cookie";
import { data } from "react-router";

import { config } from "./services";

export type JsonObject = Record<string, unknown>;

export function isObject(value: unknown): value is JsonObject {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function parseJson(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return undefined;
  }
}

export async function readJsonObject(request: Request): Promise<JsonObject> {
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(await request.arrayBuffer());
  } catch {
    return {};
  }
  const value = parseJson(text);
  return isObject(value) ? value : {};
}

export function stringField(object: JsonObject, key: string): string | null {
  const value = object[key];
  return typeof value === "string" ? value : null;
}

export function noStoreJson(body: unknown, status = 200, headers?: HeadersInit): Response {
  const response = Response.json(body, { status, headers });
  response.headers.set("Cache-Control", "no-store");
  response.headers.set("Pragma", "no-cache");
  return response;
}

export function appendQuery(uri: string, params: Record<string, string | null | undefined>): string {
  const query = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== null && value !== undefined) query.append(key, value);
  }
  return uri + (uri.includes("?") ? "&" : "?") + query.toString();
}

export async function readForm(request: Request): Promise<FormData> {
  const type = (request.headers.get("Content-Type") ?? "").split(";")[0]!.trim().toLowerCase();
  if (type !== "application/x-www-form-urlencoded" && type !== "multipart/form-data") {
    return new FormData();
  }
  let form: FormData;
  try {
    form = await request.formData();
  } catch {
    return new FormData();
  }
  const strings = new FormData();
  for (const [key, value] of form) {
    if (typeof value === "string") strings.append(key, value);
  }
  return strings;
}

export function formString(form: FormData, name: string): string | null {
  const value = form.get(name);
  return typeof value === "string" ? value : null;
}

export function getCookie(request: Request, name: string): string | undefined {
  return parse(request.headers.get("Cookie") ?? "")[name];
}

export function setCookie(name: string, value: string, maxAge: number): string {
  return serialize(name, value, {
    maxAge,
    path: config.cookiePath(),
    secure: true,
    httpOnly: true,
    sameSite: "lax",
  });
}

export function expireCookie(name: string): string {
  return serialize(name, "", {
    maxAge: 0,
    expires: new Date(0),
    path: config.cookiePath(),
    secure: true,
    httpOnly: true,
    sameSite: "lax",
  });
}

export interface ErrorAction {
  href: string;
  label: string;
  plain?: boolean;
}

export interface ErrorPageData {
  title: string;
  message: string;
  actions: ErrorAction[];
}

export function errorPage(
  title: string,
  status: number,
  { message = "", actions = [], headers }: { message?: string; actions?: ErrorAction[]; headers?: HeadersInit } = {},
) {
  return data<ErrorPageData>({ title, message, actions }, { status, headers });
}

export function notFound() {
  return errorPage("Not found", 404);
}

export function expired() {
  return errorPage("This login has expired", 400);
}

export function unverifiedForm() {
  return errorPage("This form could not be verified", 400);
}
