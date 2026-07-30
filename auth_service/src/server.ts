// import bodyParser from "body-parser";
// import cors from "cors";
import { betterAuth } from "better-auth";
import { toNodeHandler } from "better-auth/node";
import { bearer } from "better-auth/plugins";
import { jwt } from "better-auth/plugins/jwt";
import { username } from "better-auth/plugins/username";
import cors from "cors";
import type { Request, Response } from "express";
import express from "express";
import { Pool } from "pg";

const jwtSecret = process.env["JWT_SECRET"];
if (!jwtSecret) {
  console.error("FATAL: JWT_SECRET environment variable must be set");
  process.exit(1);
}

const dbhost = process.env["DB_HOST"] || "localhost";
const dbport = process.env["DB_PORT"] || "5432";
const dbname = process.env["DB_NAME"] || "authservice";
const dbuser = process.env["DB_USER"] || "postgres";
const dbpass = process.env["DB_PASS"] || "postgres";
const dbsslmode = process.env["DB_SSLMODE"] || "require";
const dsn = `postgres://${dbuser}:${dbpass}@${dbhost}:${dbport}/${dbname}?sslmode=${dbsslmode}`;
const baseURL = process.env["BETTER_AUTH_BASE_URL"];

const allowedOrigins = process.env["ALLOWED_ORIGINS"]
  ? process.env["ALLOWED_ORIGINS"].split(",")
  : ["http://localhost:7050", "http://localhost:7051"];

// Cookie security is derived from the scheme of baseURL, not from NODE_ENV. That
// coupling is easy to get wrong in the unsafe direction: a deployment served over
// TLS but configured with an http:// baseURL would issue session cookies with no
// Secure flag. Stating it explicitly keeps the flag tied to the scheme asserted
// at startup.
const useSecureCookies = baseURL?.startsWith("https://") ?? false;

export const auth = betterAuth({
  baseURL,
  // The application secret belongs at this top level. better-auth resolves it as
  // `secret` -> BETTER_AUTH_SECRET -> AUTH_SECRET -> a documented default
  // constant, and the jwt plugin's options are a separate namespace that is not
  // consulted for it. Because that chain ends in a usable default rather than an
  // error, a secret supplied anywhere else fails silently, which is what
  // assertSecretIsSafe below exists to catch.
  secret: jwtSecret,
  advanced: {
    useSecureCookies,
  },
  database: new Pool({
    connectionString: dsn,
  }),
  plugins: [
    bearer(),
    jwt(),
    username({
      maxUsernameLength: 30,
      usernameValidator: (username: string) => {
        if (username === "admin") {
          return false;
        }
        return true;
      },
    }),
  ],
  emailAndPassword: {
    enabled: true,
  },
  // Throttle credential endpoints. Sign-in is the cheapest way to attack this
  // service: a correct password yields a token that hot_storage will exchange for
  // a key share, so an unmetered sign-in endpoint is an offline-speed password
  // oracle exposed over HTTP. The tighter custom rule covers the paths where a
  // guess is worth something.
  rateLimit: {
    enabled: true,
    window: 60,
    max: 100,
    customRules: {
      "/sign-in/email": { window: 60, max: 5 },
      "/sign-in/username": { window: 60, max: 5 },
      // Sign-up is bounded to curb bulk account creation, but the budget is
      // per-IP and shared by everyone behind one address -- an office NAT or a
      // CI runner is a single client here. Left too tight it locks out
      // legitimate users rather than attackers.
      "/sign-up/email": { window: 3600, max: 30 },
      "/forget-password": { window: 3600, max: 5 },
      "/reset-password": { window: 3600, max: 5 },
    },
  },
  trustedOrigins: allowedOrigins,
});

// Fail closed unless the resolved secret is the one we supplied.
//
// This secret signs session cookies and verification tokens, and encrypts the
// JWKS private signing key at rest -- the key whose signatures hot_storage trusts
// when it releases a wallet key share. A service running on the library's default
// secret is therefore not merely misconfigured: anyone holding a copy of the
// database can decrypt that signing key using a published constant and mint
// tokens for any user. The library only refuses to boot on the default in
// production mode, so assert it here regardless of environment.
const BETTER_AUTH_DEFAULT_SECRET = "better-auth-secret-12345678901234567890";

async function assertSecretIsSafe(): Promise<void> {
  if (!baseURL) {
    console.error(
      "FATAL: BETTER_AUTH_BASE_URL must be set. Without it the issued JWTs carry " +
        "empty iss/aud claims, which hot_storage rejects.",
    );
    process.exit(1);
  }
  if (!useSecureCookies) {
    console.warn(
      `[warn] BETTER_AUTH_BASE_URL is not https (${baseURL}); session cookies are ` +
        "issued WITHOUT the Secure flag. Acceptable for local development only.",
    );
  }
  const resolved = (await auth.$context).secret;
  if (resolved === BETTER_AUTH_DEFAULT_SECRET) {
    console.error(
      "FATAL: better-auth resolved to its default secret. JWT_SECRET was not applied. " +
        "Pass it as the top-level `secret` option.",
    );
    process.exit(1);
  }
  if (resolved !== jwtSecret) {
    console.error(
      "FATAL: the resolved better-auth secret does not match JWT_SECRET. " +
        "Check for a competing BETTER_AUTH_SECRET/AUTH_SECRET in the environment.",
    );
    process.exit(1);
  }
  if (resolved.length < 32) {
    console.error(`FATAL: JWT_SECRET must be at least 32 characters (got ${resolved.length}).`);
    process.exit(1);
  }
}

const app = express();

app.use(
  cors({
    origin: allowedOrigins,
    methods: ["GET", "POST", "PUT", "DELETE"],
    credentials: true,
  }),
);

// Rate limiting is keyed on the client IP, which better-auth reads from
// x-forwarded-for. Two failure modes have to be closed off here.
//
// If the header is absent, better-auth cannot derive a key and skips rate
// limiting altogether outside development -- so the limits configured above would
// silently do nothing on a direct connection.
//
// If the header is present but untrusted, a caller can supply a fresh value per
// request and each one gets its own bucket, which evades the limit just as
// completely.
//
// So: unless a trusted proxy is declared, the header is overwritten with the
// address of the peer that actually opened the socket.
const trustProxy = process.env["TRUST_PROXY"] === "true";

app.use((req, _res, next) => {
  if (!trustProxy) {
    const socketIp = req.socket.remoteAddress;
    if (socketIp) {
      req.headers["x-forwarded-for"] = socketIp;
    } else {
      delete req.headers["x-forwarded-for"];
    }
  }
  next();
});

app.all("/api/auth/*splat", toNodeHandler(auth));

app.get("/.well-known/jwks.json", (req: Request, res: Response) => {
  req.url = "/api/auth/jwks";
  toNodeHandler(auth)(req, res);
});

app.use(express.json());

// Origin validation endpoint for nginx auth_request subrequest.
// Nginx sends X-Request-Origin header; returns 200 if allowed, 403 if not.
// Also returns X-Allowed-Origins header for CSP frame-ancestors.
app.get("/v1/projects/validate-origin", (req: Request, res: Response) => {
  // Default missing origin to a safe value that won't match any allowed origin,
  // matching the backend's pattern (ProjectController.ts defaults to "openfort.io").
  const requestOrigin = (req.headers["x-request-origin"] as string | undefined) || "openfort.io";
  const allowedOriginsStr = allowedOrigins.join(" ");

  const isAllowed = allowedOrigins.some((origin) => requestOrigin === origin);

  if (isAllowed) {
    res.set("X-Allowed-Origins", allowedOriginsStr);
    res.sendStatus(200);
  } else {
    res.sendStatus(403);
  }
});

app.get("/health", (_req: Request, res: Response) => {
  res.json({ status: "ok" });
});

const HOST = process.env["HOST"] || "localhost";
const PORT = process.env["PORT"] || 3000;

// Only listen when this module is the entry point. It doubles as the config file
// for the @better-auth/cli migration step, which imports it; binding a port on
// import would make the service appear reachable during migrations and start a
// listener nothing owns.
if (require.main === module) {
  void assertSecretIsSafe().then(() => {
    app.listen(PORT, () => {
      console.log(`Better Auth server running on http://${HOST}:${PORT}`);
    });
  });
}
