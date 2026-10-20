// Pure single purpose checks. Each returns true when the rule passes.
import { ed25519 } from "@noble/curves/ed25519.js";
import type { SiwsParams } from "./types.ts";

export function domainMatches(p: SiwsParams, expected: string): boolean {
  return p.domain === expected;
}

/** Valid on the half open interval [issuedAt, expirationTime). */
export function notYetValid(p: SiwsParams, now: Date): boolean {
  return now.getTime() < Date.parse(p.issuedAt);
}
export function isExpired(p: SiwsParams, now: Date): boolean {
  return now.getTime() >= Date.parse(p.expirationTime);
}

export function isAllowlisted(address: string, allowlist: Iterable<string> | undefined): boolean {
  if (allowlist === undefined) return true;
  for (const a of allowlist) if (a === address) return true;
  return false;
}

export function isReplay(nonce: string, seen: ReadonlySet<string>): boolean {
  return seen.has(nonce);
}

export function signatureValid(message: string, sig: Uint8Array, pub: Uint8Array): boolean {
  try {
    // zip215: false gives strict RFC 8032 verification (rejects non canonical encodings).
    return ed25519.verify(sig, new TextEncoder().encode(message), pub, { zip215: false });
  } catch {
    return false;
  }
}
