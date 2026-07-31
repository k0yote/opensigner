// Pure configuration helpers, split out of server.ts so they can be unit
// tested without a database connection.

/** Session cookies carry the Secure flag iff the public base URL is https. */
export function secureCookiesFor(baseURL: string | undefined): boolean {
  return baseURL?.startsWith("https://") ?? false;
}

/**
 * Resolves the single client address rate limiting keys on.
 *
 * better-auth reads x-forwarded-for and requires exactly one valid IP in it;
 * anything else collapses every caller into one shared bucket. Without a
 * trusted proxy the caller-supplied header is discarded in favour of the
 * socket peer, since a forged header would otherwise grant a fresh bucket per
 * request. With one trusted proxy in front, the last entry is the address the
 * proxy itself appended, which is the real client.
 */
export function resolveClientIp(
  forwardedFor: string | undefined,
  socketIp: string | undefined,
  trustProxy: boolean,
): string | undefined {
  if (!trustProxy) {
    return socketIp;
  }
  const hops = (forwardedFor ?? "")
    .split(",")
    .map((entry) => entry.trim())
    .filter(Boolean);
  return hops[hops.length - 1] ?? socketIp;
}

/** Origin allow-list check: exact match only, no prefix or suffix matching. */
export function isOriginAllowed(origin: string | undefined, allowed: string[]): boolean {
  return origin !== undefined && origin !== "" && allowed.includes(origin);
}
