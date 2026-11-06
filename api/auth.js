import { randomBytes } from "node:crypto";

const SITE_ORIGIN = "https://mrmissmit.vercel.app";
const CALLBACK_URL = `${SITE_ORIGIN}/api/callback`;
const STATE_COOKIE = "decap_oauth_state";

export default function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("X-Content-Type-Options", "nosniff");

  if (req.method !== "GET") {
    res.setHeader("Allow", "GET");
    return res.status(405).send("Method not allowed");
  }

  const clientId = process.env.OAUTH_CLIENT_ID;
  if (!clientId) {
    return res.status(500).send("OAuth is not configured on the server.");
  }

  const provider = Array.isArray(req.query?.provider) ? req.query.provider[0] : req.query?.provider;
  if (provider && provider !== "github") {
    return res.status(400).send("Unsupported OAuth provider.");
  }

  const state = randomBytes(32).toString("base64url");
  const authorizeUrl = new URL("https://github.com/login/oauth/authorize");
  authorizeUrl.searchParams.set("client_id", clientId);
  authorizeUrl.searchParams.set("redirect_uri", CALLBACK_URL);
  authorizeUrl.searchParams.set("scope", "repo,user");
  authorizeUrl.searchParams.set("state", state);

  res.setHeader(
    "Set-Cookie",
    `${STATE_COOKIE}=${state}; Path=/api; HttpOnly; Secure; SameSite=Lax; Max-Age=600`,
  );
  return res.redirect(302, authorizeUrl.toString());
}
