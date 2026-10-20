import { ed25519 } from "@noble/curves/ed25519.js";
import { base58 } from "@scure/base";
import { createMessage, type SiwsParams } from "../src/index.ts";

// Fixed test keys. Never use these for anything real.
export const SK_A = new Uint8Array(32).fill(1);
export const SK_B = new Uint8Array(32).fill(2);
export const ADDR_A = base58.encode(ed25519.getPublicKey(SK_A));
export const ADDR_B = base58.encode(ed25519.getPublicKey(SK_B));
export const DOMAIN = "app.example.com";
export const ISSUED = "2026-10-20T12:00:00.000Z";
export const EXPIRES = "2026-10-20T12:10:00.000Z";
export const NOW = new Date("2026-10-20T12:05:00.000Z");

export function params(over: Partial<SiwsParams> = {}): SiwsParams {
  return {
    domain: DOMAIN,
    address: ADDR_A,
    statement: "Sign in to Example",
    nonce: "abc123XYZ789",
    issuedAt: ISSUED,
    expirationTime: EXPIRES,
    ...over,
  };
}

export function sign(message: string, sk = SK_A): string {
  return base58.encode(ed25519.sign(new TextEncoder().encode(message), sk));
}

export function signed(over: Partial<SiwsParams> = {}, sk = SK_A) {
  const message = createMessage(params(over));
  return { message, signature: sign(message, sk) };
}
