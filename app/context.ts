import { createContext } from "react-router";

export interface RequestInfo {
  nonce: string;
  remoteAddress: string;
}

export const requestContext = createContext<RequestInfo>();
