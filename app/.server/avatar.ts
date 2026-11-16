import { createHash } from "node:crypto";

import { PNG } from "pngjs";

import { isObject, parseJson } from "./http";
import { store } from "./services";
import { now } from "./session";

export const UUID = /^(?:[0-9a-f]{32}|[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12})$/;
export const PROFILE_URL = "https://sessionserver.mojang.com/session/minecraft/profile/";
const TEXTURES_HOST = "textures.minecraft.net";
const USER_AGENT = "civauth-avatar/1.0";
const TIMEOUT = 5_000;
export const MAX_AGE = 7 * 86400;
const SIZE = 64;
const HEAD_BOX = [8, 8] as const;
const HAT_BOX = [40, 8] as const;

const PLACEHOLDER_SKIN = [0xb5, 0x8b, 0x69, 0xff] as const;
const PLACEHOLDER_MARK = [0x3f, 0x2c, 0x1e, 0xff] as const;
const PLACEHOLDER_ROWS = [
  "........",
  "..####..",
  ".##..##.",
  ".....##.",
  "....##..",
  "...##...",
  "........",
  "...##...",
];

class Unavailable extends Error {}

export async function avatarPng(uuid: string): Promise<Uint8Array> {
  uuid = uuid.replaceAll("-", "");
  const time = now();
  const cached = store.avatar(uuid);
  if (cached !== null && time - Math.trunc(Number(cached.fetched_at)) < MAX_AGE) {
    return cached.png;
  }
  let png: Uint8Array;
  try {
    png = await build(uuid);
  } catch (error) {
    console.warn(`avatar for ${uuid} could not be built`, error);
    return cached === null ? PLACEHOLDER : cached.png;
  }
  store.putAvatar(uuid, png, time);
  return png;
}

async function get(url: string): Promise<Response> {
  return fetch(url, {
    redirect: "manual",
    headers: { "User-Agent": USER_AGENT },
    signal: AbortSignal.timeout(TIMEOUT),
  });
}

export const MAX_PROFILE_BYTES = 64 * 1024;
export const MAX_SKIN_BYTES = 1024 * 1024;
export const MAX_SKIN_SIDE = 1024;

async function build(uuid: string): Promise<Uint8Array> {
  const response = await get(PROFILE_URL + uuid);
  if (response.status !== 200) {
    await response.body?.cancel();
    throw new Unavailable(`profile lookup returned ${response.status}`);
  }
  const profile = new TextDecoder().decode(await readLimited(response, MAX_PROFILE_BYTES));
  const url = skinUrl(parseJson(profile));
  if (url === null) return PLACEHOLDER;
  const skin = await get(url);
  if (skin.status !== 200) {
    await skin.body?.cancel();
    throw new Unavailable(`skin download returned ${skin.status}`);
  }
  return render(await readLimited(skin, MAX_SKIN_BYTES));
}

export async function readLimited(response: Response, max: number): Promise<Uint8Array> {
  const declared = Number(response.headers.get("Content-Length"));
  if (Number.isFinite(declared) && declared > max) {
    await response.body?.cancel();
    throw new Unavailable(`response is ${declared} bytes`);
  }
  if (!response.body) return new Uint8Array();
  const chunks: Uint8Array[] = [];
  let length = 0;
  const reader = response.body.getReader();
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    length += value.byteLength;
    if (length > max) {
      await reader.cancel();
      throw new Unavailable(`response is over ${max} bytes`);
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks);
}

const PNG_SIGNATURE = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

function checkPngHeader(png: Uint8Array): void {
  const bytes = Buffer.from(png.buffer, png.byteOffset, png.byteLength);
  if (bytes.length < 33 || !bytes.subarray(0, 8).equals(PNG_SIGNATURE) || bytes.toString("latin1", 12, 16) !== "IHDR") {
    throw new Unavailable("not a PNG");
  }
  const width = bytes.readUInt32BE(16);
  const height = bytes.readUInt32BE(20);
  if (width > MAX_SKIN_SIDE || height > MAX_SKIN_SIDE) throw new Unavailable(`skin is ${width}x${height}`);
  if (bytes[28] !== 0) throw new Unavailable("skin is interlaced");
}

export function skinUrl(profile: unknown): string | null {
  if (!isObject(profile) || !Array.isArray(profile.properties)) return null;
  for (const entry of profile.properties as unknown[]) {
    if (!isObject(entry) || entry.name !== "textures" || typeof entry.value !== "string") continue;
    const textures = parseJson(Buffer.from(entry.value, "base64").toString("utf8"));
    const skin = isObject(textures) && isObject(textures.textures) ? textures.textures.SKIN : undefined;
    const url = isObject(skin) ? textureUrl(skin.url) : null;
    if (url !== null) return url;
  }
  return null;
}

export function textureUrl(value: unknown): string | null {
  if (typeof value !== "string") return null;
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return null;
  }
  if ((url.protocol !== "http:" && url.protocol !== "https:") || url.hostname !== TEXTURES_HOST) return null;
  url.protocol = "https:";
  url.username = url.password = url.port = url.hash = "";
  return url.href;
}

interface Image {
  width: number;
  height: number;
  data: Uint8Array;
}

export function render(skinPng: Uint8Array): Uint8Array {
  checkPngHeader(skinPng);
  const decoded = PNG.sync.read(Buffer.from(skinPng));
  const image: Image = { width: decoded.width, height: decoded.height, data: decoded.data };
  if (image.width < 64 || image.height < 32) {
    throw new Unavailable(`skin is ${image.width}x${image.height}`);
  }
  let face = crop(image, HEAD_BOX);
  const hat = crop(image, HAT_BOX);
  if (hat.data.some((value, index) => index % 4 === 3 && value !== 0)) {
    face = alphaComposite(face, hat);
  }
  return toPng(scale(face, SIZE));
}

function crop(image: Image, [left, top]: readonly [number, number]): Image {
  const data = new Uint8Array(8 * 8 * 4);
  for (let y = 0; y < 8; y++) {
    const start = ((top + y) * image.width + left) * 4;
    data.set(image.data.subarray(start, start + 8 * 4), y * 8 * 4);
  }
  return { width: 8, height: 8, data };
}

function alphaComposite(dst: Image, src: Image): Image {
  const out = new Uint8Array(dst.data.length);
  const PRECISION_BITS = 7;
  const div255 = (a: number) => (((a >>> 8) + a) >>> 8) >>> 0;
  for (let i = 0; i < out.length; i += 4) {
    const sa = src.data[i + 3]!;
    if (sa === 0) {
      out.set(dst.data.subarray(i, i + 4), i);
      continue;
    }
    const blend = dst.data[i + 3]! * (255 - sa);
    const outa255 = sa * 255 + blend;
    const coef1 = Math.floor((sa * 255 * 255 * (1 << PRECISION_BITS)) / outa255);
    const coef2 = 255 * (1 << PRECISION_BITS) - coef1;
    for (let c = 0; c < 3; c++) {
      const tmp = src.data[i + c]! * coef1 + dst.data[i + c]! * coef2;
      out[i + c] = div255(tmp + (0x80 << PRECISION_BITS)) >>> PRECISION_BITS;
    }
    out[i + 3] = div255(outa255 + 0x80);
  }
  return { width: dst.width, height: dst.height, data: out };
}

function scale(image: Image, size: number): Image {
  const data = new Uint8Array(size * size * 4);
  for (let y = 0; y < size; y++) {
    const sy = Math.floor((y * image.height) / size);
    for (let x = 0; x < size; x++) {
      const sx = Math.floor((x * image.width) / size);
      const from = (sy * image.width + sx) * 4;
      data.set(image.data.subarray(from, from + 4), (y * size + x) * 4);
    }
  }
  return { width: size, height: size, data };
}

function toPng(image: Image): Uint8Array {
  const png = new PNG({ width: image.width, height: image.height });
  png.data = Buffer.from(image.data);
  return new Uint8Array(PNG.sync.write(png, { colorType: 6 }));
}

function placeholder(): Uint8Array {
  const data = new Uint8Array(8 * 8 * 4);
  PLACEHOLDER_ROWS.forEach((row, y) => {
    for (let x = 0; x < 8; x++) {
      data.set(row[x] === "#" ? PLACEHOLDER_MARK : PLACEHOLDER_SKIN, (y * 8 + x) * 4);
    }
  });
  return toPng(scale({ width: 8, height: 8, data }, SIZE));
}

export const PLACEHOLDER = placeholder();

export function pngResponse(png: Uint8Array, ifNoneMatch: string | null): Response {
  const etag = '"' + createHash("sha256").update(png).digest("hex").slice(0, 32) + '"';
  const headers = new Headers({ "Cache-Control": "public, max-age=3600", ETag: etag });
  if (fresh(ifNoneMatch, etag)) return new Response(null, { status: 304, headers });
  headers.set("Content-Type", "image/png");
  headers.set("Content-Length", String(png.byteLength));
  return new Response(png.slice(), { status: 200, headers });
}

function fresh(header: string | null, etag: string): boolean {
  if (!header) return false;
  for (let candidate of header.split(",")) {
    candidate = candidate.trim();
    if (candidate.startsWith("W/")) candidate = candidate.slice(2);
    if (candidate === "*" || candidate === etag) return true;
  }
  return false;
}
