import { betterAuth } from "better-auth";
import { toNodeHandler } from "better-auth/node";
import { bearer } from "better-auth/plugins";
import { jwt } from "better-auth/plugins/jwt";
import { username } from "better-auth/plugins/username";
import cors from "cors";
import type { Request, Response } from "express";
import express from "express";
import { Pool } from "pg";
import { isOriginAllowed, resolveClientIp, secureCookiesFor } from "./helpers";

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

// Derived from the base URL's scheme, not NODE_ENV, so a TLS deployment with an
// http:// baseURL cannot silently issue cookies without the Secure flag.
const useSecureCookies = secureCookiesFor(baseURL);

export const auth = betterAuth({
  baseURL,
  // The secret must be this top-level option; the jwt plugin's options are not
  // consulted for it, and better-auth's fallback chain ends in a usable default
  // constant rather than an error. assertStartupConfig verifies it applied.
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
  // Throttle credential endpoints: a correct password guess here yields a token
  // hot_storage will exchange for a key share. Rule keys must exactly match
  // better-auth route paths, or the rule silently never applies.
  rateLimit: {
    enabled: true,
    window: 60,
    max: 100,
    customRules: {
      "/sign-in/email": { window: 60, max: 5 },
      "/sign-in/username": { window: 60, max: 5 },
      // Per-IP budget shared by everyone behind one address (office NAT, CI
      // runner); too tight locks out legitimate users rather than attackers.
      "/sign-up/email": { window: 3600, max: 30 },
      "/request-password-reset": { window: 3600, max: 5 },
      "/reset-password": { window: 3600, max: 5 },
    },
  },
  trustedOrigins: allowedOrigins,
});

// The secret encrypts the JWKS signing key at rest, so running on the library's
// published default constant would let anyone with a database copy mint tokens.
// The library only refuses the default in production mode; assert it here
// regardless of environment.
const BETTER_AUTH_DEFAULT_SECRET = "better-auth-secret-12345678901234567890";

async function assertStartupConfig(): Promise<void> {
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
// x-forwarded-for and requires to be a single valid address -- anything it
// cannot resolve falls back to ONE bucket shared by every caller, so a forged
// or absent header either evades the limit or lets one attacker exhaust it for
// everyone. resolveClientIp rewrites the header to the one address that can be
// trusted for the deployment shape (see .env.example for TRUST_PROXY).
const trustProxy = process.env["TRUST_PROXY"] === "true";

app.use((req, _res, next) => {
  const rawForwardedFor = req.headers["x-forwarded-for"];
  const forwardedFor = Array.isArray(rawForwardedFor) ? rawForwardedFor.join(",") : rawForwardedFor;
  const clientIp = resolveClientIp(forwardedFor, req.socket.remoteAddress, trustProxy);
  if (clientIp) {
    req.headers["x-forwarded-for"] = clientIp;
  } else {
    delete req.headers["x-forwarded-for"];
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
  // A missing header is refused outright. Substituting a default domain here
  // would validate every referrer-suppressed load the moment that domain is
  // added to the allow-list.
  const requestOrigin = req.headers["x-request-origin"] as string | undefined;

  if (isOriginAllowed(requestOrigin, allowedOrigins)) {
    res.set("X-Allowed-Origins", allowedOrigins.join(" "));
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
  void (async () => {
    try {
      await assertStartupConfig();
    } catch (err) {
      console.error("FATAL: startup checks could not run:", err);
      process.exit(1);
    }
    app.listen(PORT, () => {
      console.log(`Better Auth server running on http://${HOST}:${PORT}`);
    });
  })();
}
