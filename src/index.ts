import { createMessage, parseMessage, SiwsFormatError } from "./message.ts";
import { decodeAddress, decodeSignature } from "./codec.ts";
import * as rules from "./rules.ts";
import type { VerifyInput, VerifyOptions, VerifyResult, SiwsParams } from "./types.ts";

export { createMessage, parseMessage, SiwsFormatError };
export type { SiwsParams, VerifyInput, VerifyOptions, VerifyResult, SiwsReason } from "./types.ts";

/**
 * Verify a signed SIWS message. Never throws for bad input; returns {ok:false, reason}.
 * Check order (cheap and structural first, then crypto, then policy):
 * malformed_message, address_mismatch, malformed_signature, bad_signature,
 * wrong_domain, not_yet_valid, expired, not_allowlisted, replayed_nonce.
 * On success the caller must record result.nonce in its seen store.
 *
 * The first argument is exactly the spec's {message, signature, address, allowlist, now, seen}.
 * Domain binding is configured in the optional second argument (or once via createVerifier):
 * the domain is read from the signed message and must equal one of options.domain / options.domains.
 * With no domain configured the domain is not checked; production servers should always configure it.
 */
export function verify(input: VerifyInput, options?: VerifyOptions): VerifyResult {
  let p: SiwsParams;
  let pub: Uint8Array;
  try {
    p = parseMessage(input.message);
    pub = decodeAddress(p.address);
  } catch {
    return { ok: false, reason: "malformed_message" };
  }
  if (input.address !== p.address) return { ok: false, reason: "address_mismatch" };
  let sig: Uint8Array;
  try {
    sig = decodeSignature(input.signature);
  } catch {
    return { ok: false, reason: "malformed_signature" };
  }
  if (!rules.signatureValid(input.message, sig, pub)) return { ok: false, reason: "bad_signature" };
  if (!rules.domainMatches(p, rules.allowedDomains(options))) return { ok: false, reason: "wrong_domain" };
  if (!(input.now instanceof Date) || Number.isNaN(input.now.getTime()))
    return { ok: false, reason: "malformed_message" };
  if (rules.notYetValid(p, input.now)) return { ok: false, reason: "not_yet_valid" };
  if (rules.isExpired(p, input.now)) return { ok: false, reason: "expired" };
  if (!rules.isAllowlisted(p.address, input.allowlist)) return { ok: false, reason: "not_allowlisted" };
  if (rules.isReplay(p.nonce, input.seen)) return { ok: false, reason: "replayed_nonce" };
  return { ok: true, reason: "ok", nonce: p.nonce, params: p };
}

/**
 * Bind a domain policy once and get a verifier with the exact spec signature:
 * const verifySiws = createVerifier({ domain: "app.example.com" }); verifySiws({ message, signature, address, allowlist, now, seen }).
 */
export function createVerifier(options: VerifyOptions): (input: VerifyInput) => VerifyResult {
  const frozen: VerifyOptions = { domains: rules.allowedDomains(options) ?? [] };
  return (input) => verify(input, frozen);
}
