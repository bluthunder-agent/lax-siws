# lax-siws

CI: GitHub Actions workflow (Node 20 and 22: typecheck, test, mutation check) is being added; until then run `npm ci && npm run typecheck && npm test && npm run mutate`.

Sign in with Solana (SIWS) in TypeScript: build a canonical message, then verify the ed25519 signature,
domain, time window, allowlist and nonce replay. Pure functions, no network, no clock reads.

## Install and test

```sh
npm ci
npm test          # node:test via tsx
npm run typecheck # tsc --strict
npm run mutate    # plants 19 bugs one at a time; each must make the suite fail
```

## API

```ts
import { createMessage, verify } from "lax-siws";

const message = createMessage({
  domain: "app.example.com",
  address: "<base58 pubkey>",
  statement: "Sign in to Example", // optional, single line
  nonce: "abc123XYZ789",           // 8 to 128 alphanumerics, single use
  issuedAt: "2026-10-20T12:00:00.000Z",
  expirationTime: "2026-10-20T12:10:00.000Z",
});

// wallet signs `message` (UTF-8 bytes) with signMessage, returns a 64 byte signature

const r = verify({
  message, signature /* base58 */, address /* base58 */,
  domain: "app.example.com",       // what this server expects
  allowlist: [address],            // optional; undefined = anyone, [] = nobody
  now: new Date(),
  seen: usedNonces,                // ReadonlySet<string>, never mutated
});
if (r.ok) usedNonces.add(r.nonce); // the caller records the nonce
else console.log(r.reason);
```

### Message format

```
app.example.com wants you to sign in with your Solana account:
<address>

<statement>

Nonce: <nonce>
Issued At: <ISO 8601 UTC>
Expiration Time: <ISO 8601 UTC>
```

The statement block (statement plus blank line) is omitted when there is no statement.
Parsing is strict: the parsed fields must re-serialize to the exact input, so extra, missing,
reordered or re-spaced fields, CRLF line endings and trailing newlines are all refused.

### Reasons

Checks run in this order and the first failure is returned:

| reason | meaning |
|---|---|
| `malformed_message` | text is not a canonical SIWS message, or `now` is an invalid Date |
| `address_mismatch` | caller supplied `address` differs from the address in the message |
| `malformed_signature` | signature is not base58 or is not 64 bytes |
| `bad_signature` | ed25519 verification failed (strict RFC 8032, `zip215: false`) |
| `wrong_domain` | message domain is not exactly the expected domain (no suffix or case folding) |
| `not_yet_valid` | `now` < `issuedAt` |
| `expired` | `now` >= `expirationTime` (valid window is `[issuedAt, expirationTime)`) |
| `not_allowlisted` | signer not in the allowlist |
| `replayed_nonce` | nonce is already in `seen` |

Signature is checked before policy, so an attacker cannot learn allowlist or nonce state with an unsigned message.

## Layout

- `src/types.ts` message, input and result types
- `src/message.ts` `createMessage`, strict `parseMessage`
- `src/codec.ts` length checked base58 decoding
- `src/rules.ts` pure single rule checks
- `src/index.ts` `verify` composes the rules
- `test/` node:test suites with fixed test keys
- `scripts/mutants.ts` planted bugs that the tests must catch

## Notes

- Replay protection is only as good as the caller's nonce store. Store nonces at least until expiry, atomically.
- Domain binding stops phishing only if `domain` is your real origin, not taken from the request.

MIT licensed. Built by BluThunder (bluthunder@agentmail.to).
