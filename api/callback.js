import { randomBytes, timingSafeEqual } from "node:crypto";

const SITE_ORIGIN = "https://mrmissmit.vercel.app";
const CALLBACK_URL = `${SITE_ORIGIN}/api/callback`;
const STATE_COOKIE = "decap_oauth_state";

function getCookie(req, name) {
  const cookieHeader = req.headers?.cookie || "";
  const prefix = `${name}=`;
  const value = cookieHeader.split(";").map((part) => part.trim()).find((part) => part.startsWith(prefix));
  return value ? value.slice(prefix.length) : "";
}

function sendPopupMessage(res, message, statusCode = 200) {
  const nonce = randomBytes(16).toString("base64");
  const safeMessage = JSON.stringify(message).replace(/</g, "\\u003c");
  const html = `<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><meta name="referrer" content="no-referrer"><meta name="viewport" content="width=device-width,initial-scale=1"><title>GitHub authorization</title></head>
<body>
<p>Authorization complete. You can close this window.</p>
<script nonce="${nonce}">
(() => {
  const message = ${safeMessage};
  if (!window.opener) return;
  window.opener.postMessage("authorizing:github", ${JSON.stringify(SITE_ORIGIN)});
  window.opener.postMessage(message, ${JSON.stringify(SITE_ORIGIN)});
  window.close();
})();
</script>
</body>
</html>`;

  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Content-Security-Policy", `default-src 'none'; script-src 'nonce-${nonce}'; base-uri 'none'; frame-ancestors 'none'`);
  res.setHeader(
    "Set-Cookie",
    `${STATE_COOKIE}=; Path=/api; HttpOnly; Secure; SameSite=Lax; Max-Age=0`,
  );
  return res.status(statusCode).send(html);
}

function sendError(res, message, statusCode = 400) {
  return sendPopupMessage(
    res,
    `authorization:github:error:${JSON.stringify({ message })}`,
    statusCode,
  );
}

export default async function handler(req, res) {
  if (req.method !== "GET") {
    res.setHeader("Allow", "GET");
    return res.status(405).send("Method not allowed");
  }

  const clientId = process.env.OAUTH_CLIENT_ID;
  const clientSecret = process.env.OAUTH_CLIENT_SECRET;
  if (!clientId || !clientSecret) {
    return sendError(res, "OAuth is not configured on the server.", 500);
  }

  const code = Array.isArray(req.query?.code) ? req.query.code[0] : req.query?.code;
  const state = Array.isArray(req.query?.state) ? req.query.state[0] : req.query?.state;
  const expectedState = getCookie(req, STATE_COOKIE);
  if (!code || !state || !expectedState) {
    return sendError(res, "The OAuth callback is missing required parameters.");
  }

  const receivedState = Buffer.from(state);
  const storedState = Buffer.from(expectedState);
  if (
    receivedState.length !== storedState.length ||
    !timingSafeEqual(receivedState, storedState)
  ) {
    return sendError(res, "OAuth state validation failed.");
  }

  try {
    const tokenResponse = await fetch("https://github.com/login/oauth/access_token", {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        client_id: clientId,
        client_secret: clientSecret,
        code,
        redirect_uri: CALLBACK_URL,
      }),
    });

    const tokenData = await tokenResponse.json();
    if (!tokenResponse.ok || tokenData.error || typeof tokenData.access_token !== "string") {
      console.error("GitHub OAuth token exchange failed:", tokenData.error || tokenResponse.status);
      return sendError(res, "GitHub could not complete authorization.", 502);
    }

    const authMessage = `authorization:github:success:${JSON.stringify({
      token: tokenData.access_token,
      provider: "github",
    })}`;
    return sendPopupMessage(res, authMessage);
  } catch (error) {
    console.error("GitHub OAuth callback failed:", error);
    return sendError(res, "The authorization service is temporarily unavailable.", 502);
  }
}
