import { appendQuery, isObject, parseJson } from "./http";

export interface Profile {
  uuid: string;
  name: string;
}

export class LoginFailed extends Error {
  override name = "LoginFailed";
}

export const AUTHORIZE = "https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize";
export const TOKEN = "https://login.microsoftonline.com/consumers/oauth2/v2.0/token";
export const XBOX = "https://user.auth.xboxlive.com/user/authenticate";
export const XSTS = "https://xsts.auth.xboxlive.com/xsts/authorize";
export const MC_LOGIN = "https://api.minecraftservices.com/authentication/login_with_xbox";
export const MC_PROFILE = "https://api.minecraftservices.com/minecraft/profile";

const SCOPE = "XboxLive.signin";

const TIMEOUT = 20;

const XSTS_ERRORS: Record<string, string> = {
  "2148916227": "This Xbox account is banned.",
  "2148916233": "This Microsoft account has no Xbox profile yet.",
  "2148916235": "Xbox Live is not available in this account's country.",
  "2148916236": "This account needs adult verification on the Xbox website.",
  "2148916237": "This account needs adult verification on the Xbox website.",
  "2148916238": "This is a child account and must be added to a family group.",
};

export class MojangChain {
  readonly clientId: string;
  readonly clientSecret: string;
  readonly redirectUri: string;

  constructor(clientId: string, clientSecret: string, redirectUri: string) {
    this.clientId = clientId;
    this.clientSecret = clientSecret;
    this.redirectUri = redirectUri;
  }

  loginUrl(state: string): string {
    return appendQuery(AUTHORIZE, {
      client_id: this.clientId,
      response_type: "code",
      redirect_uri: this.redirectUri,
      response_mode: "query",
      scope: SCOPE,
      state,
    });
  }

  async authenticate(code: string): Promise<Profile> {
    const msToken = await this.#microsoftToken(code);
    const [xboxToken, userHash] = await this.#xboxToken(msToken);
    const xstsToken = await this.#xstsToken(xboxToken);
    const mcToken = await this.#minecraftToken(userHash, xstsToken);
    return this.#minecraftProfile(mcToken);
  }

  async #microsoftToken(code: string): Promise<string> {
    const [status, body] = await this.#post(
      TOKEN,
      {
        client_id: this.clientId,
        client_secret: this.clientSecret,
        code,
        grant_type: "authorization_code",
        redirect_uri: this.redirectUri,
        scope: SCOPE,
      },
      false,
    );
    if (status !== 200) throw new LoginFailed("Microsoft rejected the sign-in.");
    return field(body, "access_token", "Microsoft returned no access token.");
  }

  async #xboxToken(msToken: string): Promise<[string, string]> {
    const [status, body] = await this.#post(
      XBOX,
      {
        Properties: {
          AuthMethod: "RPS",
          SiteName: "user.auth.xboxlive.com",
          RpsTicket: `d=${msToken}`,
        },
        RelyingParty: "http://auth.xboxlive.com",
        TokenType: "JWT",
      },
      true,
    );
    if (status !== 200) throw new LoginFailed("Xbox Live rejected the sign-in.");
    const data = decode(body);
    const claims = data.DisplayClaims;
    const xui = isObject(claims) ? claims.xui : undefined;
    const first = Array.isArray(xui) && xui.length > 0 && isObject(xui[0]) ? xui[0] : {};
    const userHash = first.uhs;
    const token = data.Token;
    if (typeof token !== "string" || typeof userHash !== "string") {
      throw new LoginFailed("Xbox Live returned an unexpected response.");
    }
    return [token, userHash];
  }

  async #xstsToken(xboxToken: string): Promise<string> {
    const [status, body] = await this.#post(
      XSTS,
      {
        Properties: { SandboxId: "RETAIL", UserTokens: [xboxToken] },
        RelyingParty: "rp://api.minecraftservices.com/",
        TokenType: "JWT",
      },
      true,
    );
    if (status === 401) {
      const data = decode(body);
      const code = "XErr" in data ? data.XErr : "";
      throw new LoginFailed(XSTS_ERRORS[String(code)] ?? "Xbox Live would not authorize this account.");
    }
    if (status !== 200) throw new LoginFailed("Xbox Live would not authorize this account.");
    return field(body, "Token", "Xbox Live returned an unexpected response.");
  }

  async #minecraftToken(userHash: string, xstsToken: string): Promise<string> {
    const [status, body] = await this.#post(MC_LOGIN, { identityToken: `XBL3.0 x=${userHash};${xstsToken}` }, true);
    if (status === 403) {
      console.error("civauth: Minecraft services rejected this application registration (403). ");
      throw new LoginFailed("Minecraft login is misconfigured on this server.");
    }
    if (status !== 200) throw new LoginFailed("Minecraft services rejected the sign-in.");
    return field(body, "access_token", "Minecraft services returned no access token.");
  }

  async #minecraftProfile(mcToken: string): Promise<Profile> {
    const [status, body] = await this.#send(MC_PROFILE, null, {
      Authorization: `Bearer ${mcToken}`,
      Accept: "application/json",
    });
    if (status === 404) {
      throw new LoginFailed("This Microsoft account does not own Minecraft: Java Edition.");
    }
    if (status !== 200) throw new LoginFailed("Could not read the Minecraft profile.");
    const data = decode(body);
    const id = data.id;
    const name = data.name;
    if (typeof id !== "string" || typeof name !== "string" || !/^[0-9a-fA-F]{32}$/.test(id)) {
      throw new LoginFailed("Minecraft services returned an unexpected profile.");
    }
    return { uuid: id.toLowerCase(), name };
  }

  #post(url: string, payload: Record<string, unknown>, asJson: boolean): Promise<[number, string]> {
    if (asJson) {
      return this.#send(url, JSON.stringify(payload), {
        "Content-Type": "application/json",
        Accept: "application/json",
      });
    }
    return this.#send(url, new URLSearchParams(payload as Record<string, string>).toString(), {
      "Content-Type": "application/x-www-form-urlencoded",
      Accept: "application/json",
    });
  }

  async #send(url: string, body: string | null, headers: Record<string, string>): Promise<[number, string]> {
    if (!url.startsWith("https://")) throw new Error("not an https URL");
    try {
      const response = await fetch(url, {
        method: body === null ? "GET" : "POST",
        headers,
        body,
        redirect: "manual",
        signal: AbortSignal.timeout(TIMEOUT * 1000),
      });
      return [response.status, await response.text()];
    } catch (error) {
      console.error(`civauth: request to ${new URL(url).hostname} failed: ${(error as Error)?.name ?? typeof error}`);
      return [0, ""];
    }
  }
}

function decode(body: string): Record<string, unknown> {
  const data = parseJson(body);
  return isObject(data) ? data : {};
}

function field(body: string, name: string, error: string): string {
  const value = decode(body)[name];
  if (typeof value !== "string" || value === "") throw new LoginFailed(error);
  return value;
}
