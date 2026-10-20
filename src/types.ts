/** Fields of a Sign in with Solana message. Times are ISO 8601 UTC strings. */
export interface SiwsParams {
  /** RFC 3986 authority requesting the sign in, for example "app.example.com". */
  domain: string;
  /** Base58 ed25519 public key (32 bytes) of the signer. */
  address: string;
  /** Optional human readable statement. Single line, no line breaks. */
  statement?: string;
  /** Single use random token, 8 to 128 chars of [A-Za-z0-9]. */
  nonce: string;
  /** When the message was issued. */
  issuedAt: string;
  /** When the message stops being valid. Must be after issuedAt. */
  expirationTime: string;
}

export type SiwsReason =
  | "ok"
  | "malformed_message"
  | "address_mismatch"
  | "malformed_signature"
  | "bad_signature"
  | "wrong_domain"
  | "not_yet_valid"
  | "expired"
  | "not_allowlisted"
  | "replayed_nonce";

export interface VerifyInput {
  /** The exact message text that was signed. */
  message: string;
  /** Base58 ed25519 signature (64 bytes). */
  signature: string;
  /** Base58 address the caller claims signed. Must equal the address inside the message. */
  address: string;
  /** Domain the verifier expects. The message domain must match exactly. */
  domain: string;
  /** Addresses allowed to sign in. Undefined means no allowlist; an empty list allows nobody. */
  allowlist?: Iterable<string>;
  /** Verification time. Required so verification is deterministic. */
  now: Date;
  /** Nonces already consumed. Read only; never mutated. */
  seen: ReadonlySet<string>;
}

export type VerifyResult =
  | { ok: true; reason: "ok"; nonce: string; params: SiwsParams }
  | { ok: false; reason: Exclude<SiwsReason, "ok"> };
