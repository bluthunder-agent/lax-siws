import type { SiwsParams } from "./types.ts";
import { decodeAddress } from "./codec.ts";
import { SiwsFormatError } from "./errors.ts";

export const HEADER_SUFFIX = " wants you to sign in with your Solana account:";
const DOMAIN_RE = /^[A-Za-z0-9.-]+(:[0-9]{1,5})?$/;
const NONCE_RE = /^[A-Za-z0-9]{8,128}$/;
// Strict UTC ISO 8601 with optional milliseconds, as produced by Date.prototype.toISOString.
const ISO_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3})?Z$/;

export { SiwsFormatError };

function parseIso(name: string, v: string): number {
  if (!ISO_RE.test(v)) throw new SiwsFormatError(`${name} must be UTC ISO 8601`);
  const t = Date.parse(v);
  if (Number.isNaN(t)) throw new SiwsFormatError(`${name} is not a real date`);
  return t;
}

/** Validate params; throws SiwsFormatError. Shared by createMessage and parseMessage. */
export function validateParams(p: SiwsParams): void {
  if (!DOMAIN_RE.test(p.domain)) throw new SiwsFormatError("invalid domain");
  decodeAddress(p.address); // throws on bad base58 or wrong length
  if (p.statement !== undefined && (p.statement === "" || /[\r\n]/.test(p.statement)))
    throw new SiwsFormatError("statement must be a non empty single line");
  if (!NONCE_RE.test(p.nonce)) throw new SiwsFormatError("nonce must be 8 to 128 alphanumerics");
  const iat = parseIso("issuedAt", p.issuedAt);
  const exp = parseIso("expirationTime", p.expirationTime);
  if (exp <= iat) throw new SiwsFormatError("expirationTime must be after issuedAt");
}

/** Build the canonical SIWS message text. Throws SiwsFormatError on invalid params. */
export function createMessage(p: SiwsParams): string {
  validateParams(p);
  const lines = [`${p.domain}${HEADER_SUFFIX}`, p.address, ""];
  if (p.statement !== undefined) lines.push(p.statement, "");
  lines.push(`Nonce: ${p.nonce}`, `Issued At: ${p.issuedAt}`, `Expiration Time: ${p.expirationTime}`);
  return lines.join("\n");
}

function field(line: string | undefined, key: string): string {
  const prefix = `${key}: `;
  if (line === undefined || !line.startsWith(prefix)) throw new SiwsFormatError(`expected ${key}`);
  return line.slice(prefix.length);
}

/**
 * Strictly parse a SIWS message. The result must re-serialize byte for byte,
 * so extra, missing, reordered or re-spaced fields are all refused.
 */
export function parseMessage(text: string): SiwsParams {
  const lines = text.split("\n");
  const header = lines[0] ?? "";
  if (!header.endsWith(HEADER_SUFFIX)) throw new SiwsFormatError("bad header");
  const domain = header.slice(0, -HEADER_SUFFIX.length);
  const address = lines[1] ?? "";
  if (lines[2] !== "") throw new SiwsFormatError("expected blank line after address");
  let i = 3;
  let statement: string | undefined;
  if (!(lines[i] ?? "").startsWith("Nonce: ")) {
    statement = lines[i];
    if (lines[i + 1] !== "") throw new SiwsFormatError("expected blank line after statement");
    i += 2;
  }
  const nonce = field(lines[i], "Nonce");
  const issuedAt = field(lines[i + 1], "Issued At");
  const expirationTime = field(lines[i + 2], "Expiration Time");
  if (lines.length !== i + 3) throw new SiwsFormatError("unexpected trailing content");
  const p: SiwsParams = { domain, address, nonce, issuedAt, expirationTime };
  if (statement !== undefined) p.statement = statement;
  if (createMessage(p) !== text) throw new SiwsFormatError("non canonical message");
  return p;
}
