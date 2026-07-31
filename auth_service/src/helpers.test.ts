import { describe, expect, it } from "vitest";
import { isOriginAllowed, resolveClientIp, secureCookiesFor } from "./helpers";

describe("secureCookiesFor", () => {
  it("enables Secure cookies for an https base URL", () => {
    expect(secureCookiesFor("https://auth.example.com")).toBe(true);
  });

  it("disables Secure cookies for http", () => {
    expect(secureCookiesFor("http://localhost:7052")).toBe(false);
  });

  it("disables Secure cookies when the base URL is unset", () => {
    expect(secureCookiesFor(undefined)).toBe(false);
  });
});

describe("resolveClientIp", () => {
  it("discards a caller-supplied header when no proxy is trusted", () => {
    expect(resolveClientIp("6.6.6.6", "10.0.0.9", false)).toBe("10.0.0.9");
  });

  it("uses the socket peer when no proxy is trusted and no header is sent", () => {
    expect(resolveClientIp(undefined, "10.0.0.9", false)).toBe("10.0.0.9");
  });

  it("returns undefined when nothing trustworthy is available", () => {
    expect(resolveClientIp("6.6.6.6", undefined, false)).toBeUndefined();
  });

  it("takes the proxy-appended (last) hop when the proxy is trusted", () => {
    // The leftmost entries are client-controlled; only the entry our own proxy
    // appended is trustworthy.
    expect(resolveClientIp("6.6.6.6, 7.7.7.7, 192.0.2.10", "172.18.0.2", true)).toBe("192.0.2.10");
  });

  it("handles a single-hop header when the proxy is trusted", () => {
    expect(resolveClientIp("192.0.2.10", "172.18.0.2", true)).toBe("192.0.2.10");
  });

  it("falls back to the socket peer when the trusted proxy sent no header", () => {
    expect(resolveClientIp(undefined, "172.18.0.2", true)).toBe("172.18.0.2");
    expect(resolveClientIp(" , ", "172.18.0.2", true)).toBe("172.18.0.2");
  });
});

describe("isOriginAllowed", () => {
  const allowed = ["http://localhost:7050", "http://localhost:7051"];

  it("accepts an exact match", () => {
    expect(isOriginAllowed("http://localhost:7050", allowed)).toBe(true);
  });

  it("refuses a missing origin rather than defaulting it", () => {
    expect(isOriginAllowed(undefined, allowed)).toBe(false);
    expect(isOriginAllowed("", allowed)).toBe(false);
  });

  it("refuses prefix and suffix lookalikes", () => {
    expect(isOriginAllowed("http://localhost:7050.evil.example", allowed)).toBe(false);
    expect(isOriginAllowed("http://localhost:705", allowed)).toBe(false);
  });
});
