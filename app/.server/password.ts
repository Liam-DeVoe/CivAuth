import { createHash, pbkdf2, randomInt, scrypt, timingSafeEqual, type ScryptOptions } from "node:crypto";
import { promisify } from "node:util";

const scryptAsync = promisify(scrypt) as (
  password: Buffer,
  salt: Buffer,
  keylen: number,
  options: ScryptOptions,
) => Promise<Buffer>;
const pbkdf2Async = promisify(pbkdf2);

const SALT_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
const DEFAULT_PBKDF2_ITERATIONS = 1_000_000;

function genSalt(length: number): string {
  if (length <= 0) throw new Error("Salt length must be at least 1.");
  let salt = "";
  for (let i = 0; i < length; i++) salt += SALT_CHARS[randomInt(SALT_CHARS.length)];
  return salt;
}

async function hashInternal(method: string, salt: string, password: string): Promise<[string, string]> {
  const [name, ...args] = method.split(":");
  const saltBytes = Buffer.from(salt, "utf8");
  const passwordBytes = Buffer.from(password, "utf8");

  if (name === "scrypt") {
    let n = 2 ** 15;
    let r = 8;
    let p = 1;
    if (args.length > 0) {
      const parsed = args.map(parseInteger);
      if (parsed.length !== 3 || parsed.some((value) => value === null)) {
        throw new Error(`invalid scrypt parameters: ${method}`);
      }
      [n, r, p] = parsed as [number, number, number];
    }
    const maxmem = 132 * n * r * p;
    const digest = await scryptAsync(passwordBytes, saltBytes, 64, { N: n, r, p, maxmem });
    return [digest.toString("hex"), `scrypt:${n}:${r}:${p}`];
  }

  if (name === "pbkdf2") {
    let hashName = "sha256";
    let iterations = DEFAULT_PBKDF2_ITERATIONS;
    if (args.length === 1) {
      hashName = args[0]!;
    } else if (args.length === 2) {
      hashName = args[0]!;
      const parsed = parseInteger(args[1]!);
      if (parsed === null) throw new Error(`invalid pbkdf2 parameters: ${method}`);
      iterations = parsed;
    } else if (args.length > 2) {
      throw new Error(`invalid pbkdf2 parameters: ${method}`);
    }
    const digestSize = createHash(hashName).digest().length;
    const digest = await pbkdf2Async(passwordBytes, saltBytes, iterations, digestSize, hashName);
    return [digest.toString("hex"), `pbkdf2:${hashName}:${iterations}`];
  }

  throw new Error(`unsupported password hash method: ${name}`);
}

function parseInteger(value: string): number | null {
  return /^\d+$/.test(value) ? Number(value) : null;
}

export async function generatePasswordHash(password: string, method = "scrypt", saltLength = 16): Promise<string> {
  const salt = genSalt(saltLength);
  const [hash, actualMethod] = await hashInternal(method, salt, password);
  return `${actualMethod}$${salt}$${hash}`;
}

export async function checkPasswordHash(pwhash: string, password: string): Promise<boolean> {
  const parts = splitMax(pwhash, "$", 2);
  if (parts.length < 3) return false;
  const [method, salt, hashval] = parts as [string, string, string];
  const [computed] = await hashInternal(method, salt, password);
  return compareDigest(computed, hashval);
}

function splitMax(value: string, separator: string, maxsplit: number): string[] {
  const out: string[] = [];
  let rest = value;
  while (out.length < maxsplit) {
    const index = rest.indexOf(separator);
    if (index === -1) break;
    out.push(rest.slice(0, index));
    rest = rest.slice(index + separator.length);
  }
  out.push(rest);
  return out;
}

function compareDigest(a: string, b: string): boolean {
  const left = Buffer.from(a, "utf8");
  const right = Buffer.from(b, "utf8");
  if (left.length !== right.length) return false;
  return timingSafeEqual(left, right);
}
