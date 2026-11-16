import { Notice } from "../components/ui";
import { config } from "../.server/services";
import type { Route } from "./+types/permissions";

const XSTS =
  "https://learn.microsoft.com/en-us/gaming/gdk/docs/services/fundamentals" +
  "/s2s-auth-calls/service-authentication/security-tokens/live-security-tokens";

export function loader() {
  return { address: config.joinAddress };
}

export default function Permissions({ loaderData: { address } }: Route.ComponentProps) {
  return (
    <>
      <title>Permissions - CivAuth</title>
      <div className="title">Permissions</div>
      <Notice>
        <div className="text">
          <span className="strong">TLDR:</span> <span className="em">Log in with Minecraft</span> grants certain
          theoretical permissions on your Minecraft account to CivAuth for 4 days, including the ability to join servers
          as your account. CivAuth never uses these permissions.
        </div>
        <div className="text">
          I encourage you to use the <span className="em">Verify through server</span> authentication method instead if
          this makes you uncomfortable.
        </div>
        <div className="text">
          I care about giving you the information you need to make an informed decision. Read this page for details.
        </div>
      </Notice>
      <div className="text">CivAuth has two authentication methods:</div>
      <div className="list">
        <div className="list__item">Log in with Minecraft</div>
        <div className="list__item">Verify through server</div>
      </div>
      <div className="heading">Log in with Minecraft</div>
      <div className="text">
        <span className="em">Log in with Minecraft</span> asks you to sign in with your Microsoft account
        <span className="footnote-ref">
          <a href="#fn1" id="ref1">
            1
          </a>
        </span>{" "}
        using <a href="https://en.wikipedia.org/wiki/OAuth">OAuth</a>. CivAuth performs the following authentication
        chain:
      </div>
      <div className="list">
        <div className="list__item">
          Asks the user (you) to sign in to Microsoft. CivAuth requests the{" "}
          <span className="code">XboxLive.signin</span> scope and receives a Microsoft access token.
        </div>
        <div className="list__item">CivAuth exchanges the Microsoft access token for an Xbox user token.</div>
        <div className="list__item">
          CivAuth exchanges the Xbox user token for an <a href={XSTS}>XSTS token</a>.
        </div>
        <div className="list__item">CivAuth exchanges the XSTS token for a Minecraft access token.</div>
      </div>
      <div className="text">This results in four access tokens:</div>
      <table className="grid">
        <tbody>
          <tr>
            <th>Token</th>
            <th>Expires after</th>
            <th>Permissions</th>
          </tr>
          <tr>
            <td>Microsoft access token</td>
            <td>1 hour</td>
            <td>None</td>
          </tr>
          <tr>
            <td>Xbox user token</td>
            <td>4 days</td>
            <td>Read your Xbox Live gamertag and friends list</td>
          </tr>
          <tr>
            <td>XSTS token</td>
            <td>16 hours</td>
            <td>None</td>
          </tr>
          <tr>
            <td>Minecraft access token</td>
            <td>24 hours</td>
            <td>
              Join servers as your account
              <br />
              Change your Minecraft skin, cape, or username
            </td>
          </tr>
        </tbody>
      </table>
      <div className="text">
        Unfortunately, this is the minimum possible set of permissions CivAuth can request. This is the same set of
        permissions granted when using Minecraft launchers like <a href="https://prismlauncher.org/">Prism</a>. The
        difference is those launchers receive indefinite access to these permissions, while the permissions granted to
        CivAuth expire after 4 days.
      </div>
      <div className="heading">Verify through server</div>
      <div className="text">
        <span className="em">Verify through server</span> asks you to join the minecraft server at{" "}
        <span className="code">{address}</span>. You will be kicked with a message containing a verification code. Enter
        the verification code on CivAuth to verify your account.
      </div>
      <div className="text">No permissions on your Minecraft account are granted to CivAuth.</div>
      <div className="rule"></div>
      <div className="footnotes">
        <div className="footnotes__item" id="fn1">
          Microsoft owns Minecraft. Each Minecraft account is tied to a Microsoft account. <a href="#ref1">↩</a>
        </div>
      </div>
    </>
  );
}
