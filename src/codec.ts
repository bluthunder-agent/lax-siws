import { base58 } from "@scure/base";
import { SiwsFormatError } from "./errors.ts";

function decodeExact(v: string, len: number, what: string): Uint8Array {
  let bytes: Uint8Array;
  try {
    bytes = base58.decode(v);
  } catch {
    throw new SiwsFormatError(`${what} is not base58`);
  }
  if (bytes.length !== len) throw new SiwsFormatError(`${what} must be ${len} bytes`);
  return bytes;
}

export const decodeAddress = (v: string) => decodeExact(v, 32, "address");
export const decodeSignature = (v: string) => decodeExact(v, 64, "signature");
