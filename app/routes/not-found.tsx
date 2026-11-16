import { notFound } from "../.server/http";

export function loader(): never {
  throw notFound();
}

export default function NotFound() {
  return null;
}
