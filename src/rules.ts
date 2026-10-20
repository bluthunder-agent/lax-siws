// Pure single purpose checks. Each returns true when the rule passes.
import { ed25519 } from "@noble/curves/ed25519.js";
import type { SiwsParams } from "./types.ts";

/** Exact match against the configured domains. undefined means no domain policy configured. */
export function domainMatches(p: SiwsParams, allowed: Iterable<string> | undefined): boolean {
  if (allowed === undefined) return true;
  for (const d of allowed) if (p.domain === d) return true;
  return false;
}

/** Merge options.domain and options.domains into one list, or undefined when neither is set. */
export function allowedDomains(o: { domain?: string; domains?: Iterable<string> } | undefined): string[] | undefined {
  if (o === undefined || (o.domain === undefined && o.domains === undefined)) return undefined;
  return [...(o.domain !== undefined ? [o.domain] : []), ...(o.domains ?? [])];
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
