import { Link } from "react-router";

import { Notice } from "../components/ui";
import { config } from "../.server/services";
import { REFRESH_TTL, TOKEN_TTL } from "../.server/constants";
import type { Route } from "./+types/docs";

export function loader() {
  return {
    issuer: config.issuer,
    tokenTtl: Math.floor(TOKEN_TTL / 86400),
    refreshTtl: Math.floor(REFRESH_TTL / 86400),
  };
}

export default function Docs({ loaderData: { issuer, tokenTtl, refreshTtl } }: Route.ComponentProps) {
  return (
    <>
      <title>Docs - CivAuth</title>
      <div className="title">Docs</div>
      <div className="text">
        CivAuth lets people sign into your site with their Minecraft account. CivAuth apps are standard OAuth
        applications. The relevant URLs are:
      </div>
      <table className="grid">
        <tbody>
          <tr>
            <th>Authorization</th>
            <td>
              <span className="code">{issuer}/oauth/authorize</span>
            </td>
          </tr>
          <tr>
            <th>Token</th>
            <td>
              <span className="code">{issuer}/oauth/token</span>
            </td>
          </tr>
          <tr>
            <th>User</th>
            <td>
              <span className="code">{issuer}/oauth/user</span>
            </td>
          </tr>
        </tbody>
      </table>
      <div className="text">See below for details.</div>
      <div className="heading">1. Register an app</div>
      <div className="text">
        First, register an app at <Link to="/apps">OAuth apps</Link>.
      </div>
      <div className="heading">2. Authorize a user with CivAuth</div>
      <div className="text">
        When you want a user to log in with CivAuth, redirect them to{" "}
        <span className="code">https://civauth.civwiki.org/oauth/authorize</span>, with the following query parameters:
      </div>
      <div className="codeblock">
        {`GET ${issuer}/oauth/authorize
    ?response_type=code
    &client_id=3f9a1c
    &redirect_uri=https%3A%2F%2Fexample.com%2Fcallback
    &state=8c1f0e`}
      </div>
      <table className="grid">
        <tbody>
          <tr>
            <th>
              <span className="code">response_type</span>
            </th>
            <td>
              Required. Must be <span className="code">code</span>.
            </td>
          </tr>
          <tr>
            <th>
              <span className="code">client_id</span>
            </th>
            <td>Required. The client id of your app.</td>
          </tr>
          <tr>
            <th>
              <span className="code">redirect_uri</span>
            </th>
            <td>
              Required. Must be listed as a redirect URI on your app. The user will be redirected here after they
              authorize your app.
            </td>
          </tr>
          <tr>
            <th>
              <span className="code">state</span>
            </th>
            <td>
              Optional. If passed, sent unchanged in the redirect URI. Used to tie the callback to the request that
              started the login, for security.
            </td>
          </tr>
          <tr>
            <th>
              <span className="code">code_challenge</span>
            </th>
            <td>
              Optional. Used for security; see <a href="https://www.rfc-editor.org/rfc/rfc7636">PKCE</a>. If sent, also
              send <span className="code">code_challenge_method=S256</span>.
            </td>
          </tr>
        </tbody>
      </table>
      <div className="text">
        For now, there is no <span className="code">scope</span> parameter. Each app gets the user's Minecraft name and
        UUID.
      </div>
      <div className="text">
        Once the user approves your app, they are redirected to the url in <span className="code">redirect_uri</span>,
        with a code:
      </div>
      <div className="codeblock">https://example.com/callback?code=Qm9vbXNoYWthbGFrYQ&amp;state=8c1f0e</div>
      <Notice label="Note">
        If the user declines, the callback contains <span className="code">error</span> and{" "}
        <span className="code">error_description</span> instead. See{" "}
        <a href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2.1">RFC 6749 §4.1.2.1</a>.
      </Notice>
      <div className="heading" id="exchange">
        3. Exchange the code for a token
      </div>
      <div className="text">
        Once you have a code from CivAuth, exchange it for a token by sending a POST to{" "}
        <span className="code">https://civauth.civwiki.org/oauth/token</span>:
      </div>
      <div className="codeblock">
        {`curl -d grant_type=authorization_code \\
  -d client_id=3f9a1c \\
  -d client_secret=CLIENT_SECRET \\
  -d code=Qm9vbXNoYWthbGFrYQ \\
  -d redirect_uri=https://example.com/callback \\
  ${issuer}/oauth/token`}
      </div>
      <table className="grid">
        <tbody>
          <tr>
            <th>
              <span className="code">grant_type</span>
            </th>
            <td>
              Required. Must be <span className="code">authorization_code</span>.
            </td>
          </tr>
          <tr>
            <th>
              <span className="code">client_id</span>
            </th>
            <td>Required. Your app's client id.</td>
          </tr>
          <tr>
            <th>
              <span className="code">client_secret</span>
            </th>
            <td>Required. Your app's secret.</td>
          </tr>
          <tr>
            <th>
              <span className="code">code</span>
            </th>
            <td>Required. The code from the callback.</td>
          </tr>
          <tr>
            <th>
              <span className="code">redirect_uri</span>
            </th>
            <td>Required. The same redirect URI from the authorization request.</td>
          </tr>
          <tr>
            <th>
              <span className="code">code_verifier</span>
            </th>
            <td>
              Optional. Required if you sent <span className="code">code_challenge</span>.
            </td>
          </tr>
        </tbody>
      </table>
      <div className="text">A successful exchange returns:</div>
      <div className="codeblock">
        {`{"access_token": "oJ3kZQ8vT2mXpL5wR9bYcH1nAeKdG7sUfV4jMqW0xEo", "token_type": "Bearer", "expires_in": ${tokenTtl * 86400}, "refresh_token": "Xp2vN7dKq4RtW9yBcL3mHf8sJa6ZgUe1oVi5TnPk0Cw"}`}
      </div>
      <div className="text">{`The access token lasts ${tokenTtl} days. The refresh token lasts ${refreshTtl} days.`}</div>
      <div className="heading">4. Look up the user</div>
      <div className="text">Use the access token to look up the user:</div>
      <div className="codeblock">
        {`curl -H 'Authorization: Bearer oJ3kZQ8vT2mXpL5wR9bYcH1nAeKdG7sUfV4jMqW0xEo' ${issuer}/oauth/user`}
      </div>
      <div className="codeblock">{`{"uuid": "069a79f4-44e9-4726-a5be-fca90e38aaf5", "name": "Notch"}`}</div>
      <div className="text">This returns the UUID and name of the Minecraft account.</div>
      <div className="heading" id="refresh">
        5. Refresh an access token
      </div>
      <div className="text">
        When an access token expires, you can refresh it using the refresh token. POST to{" "}
        <span className="code">https://civauth.civwiki.org/oauth/token</span>:
      </div>
      <div className="codeblock">
        {`curl -d grant_type=refresh_token \\
  -d client_id=3f9a1c \\
  -d client_secret=CLIENT_SECRET \\
  -d refresh_token=Xp2vN7dKq4RtW9yBcL3mHf8sJa6ZgUe1oVi5TnPk0Cw \\
  ${issuer}/oauth/token`}
      </div>
      <div className="text">
        The response is the same as in <a href="#exchange">the initial token exchange</a>.
      </div>
    </>
  );
}
