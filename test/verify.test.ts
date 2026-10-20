import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { base58 } from "@scure/base";
import { verify } from "../src/index.ts";
import { ADDR_A, ADDR_B, DOMAIN, EXPIRES, ISSUED, NOW, SK_B, sign, signed } from "./helpers.ts";

const base = () => {
  const { message, signature } = signed();
  return { message, signature, address: ADDR_A, domain: DOMAIN, now: NOW, seen: new Set<string>(), allowlist: [ADDR_A] };
};

describe("required cases", () => {
  test("valid: well formed, signed, in window, allowlisted, fresh nonce", () => {
    const r = verify(base());
    assert.equal(r.ok, true);
    assert.equal(r.reason, "ok");
    if (r.ok) {
      assert.equal(r.nonce, "abc123XYZ789");
      assert.equal(r.params.address, ADDR_A);
    }
  });

  test("wrong domain: signed for another site", () => {
    assert.deepEqual(verify({ ...base(), domain: "evil.example.com" }), { ok: false, reason: "wrong_domain" });
  });

  test("wrong domain: suffix and case lookalikes are refused", () => {
    for (const domain of ["app.example.co", "pp.example.com", "APP.example.com", "app.example.com:443"])
      assert.equal(verify({ ...base(), domain }).reason, "wrong_domain", domain);
  });

  test("wrong domain: message for a parent domain is refused", () => {
    const m = signed({ domain: "example.com" });
    assert.equal(verify({ ...base(), ...m }).reason, "wrong_domain");
  });

  test("expired: now after expirationTime", () => {
    assert.equal(verify({ ...base(), now: new Date("2026-10-20T13:00:00.000Z") }).reason, "expired");
  });

  test("replayed nonce: nonce already in seen", () => {
    assert.deepEqual(verify({ ...base(), seen: new Set(["abc123XYZ789"]) }), { ok: false, reason: "replayed_nonce" });
  });

  test("not allowlisted: valid signer outside the list", () => {
    assert.equal(verify({ ...base(), allowlist: [ADDR_B] }).reason, "not_allowlisted");
  });

  test("malformed signature: bad base58, wrong length, empty", () => {
    const sig = base().signature;
    for (const signature of ["0OIl" + sig.slice(4), base58.encode(new Uint8Array(63)), base58.encode(new Uint8Array(65)), ""])
      assert.equal(verify({ ...base(), signature }).reason, "malformed_signature", signature);
  });
});

describe("time window boundaries", () => {
  test("exactly at issuedAt is valid", () => {
    assert.equal(verify({ ...base(), now: new Date(ISSUED) }).ok, true);
  });
  test("one millisecond before issuedAt is not yet valid", () => {
    assert.equal(verify({ ...base(), now: new Date(Date.parse(ISSUED) - 1) }).reason, "not_yet_valid");
  });
  test("one millisecond before expiry is valid", () => {
    assert.equal(verify({ ...base(), now: new Date(Date.parse(EXPIRES) - 1) }).ok, true);
  });
  test("exactly at expirationTime is expired", () => {
    assert.equal(verify({ ...base(), now: new Date(EXPIRES) }).reason, "expired");
  });
  test("invalid now is refused, not treated as valid", () => {
    assert.equal(verify({ ...base(), now: new Date("nope") }).ok, false);
  });
});

describe("signature binding", () => {
  test("signature by another key is refused", () => {
    const { message } = signed();
    assert.equal(verify({ ...base(), signature: sign(message, SK_B) }).reason, "bad_signature");
  });

  test("tampered message field invalidates signature", () => {
    const { message, signature } = signed();
    const tampered = message.replace("abc123XYZ789", "abc123XYZ780");
    assert.equal(verify({ ...base(), message: tampered, signature }).reason, "bad_signature");
  });

  test("signer must match the address in the message", () => {
    const { message } = signed({ address: ADDR_B });
    const r = verify({ ...base(), message, signature: sign(message, SK_B), address: ADDR_A });
    assert.equal(r.reason, "address_mismatch");
  });

  test("message for B signed by A is refused even when caller claims B", () => {
    const { message } = signed({ address: ADDR_B });
    const r = verify({ ...base(), message, signature: sign(message), address: ADDR_B, allowlist: [ADDR_B] });
    assert.equal(r.reason, "bad_signature");
  });

  test("valid message for another allowlisted key passes", () => {
    const m = signed({ address: ADDR_B }, SK_B);
    assert.equal(verify({ ...base(), ...m, address: ADDR_B, allowlist: [ADDR_A, ADDR_B] }).ok, true);
  });
});

describe("allowlist and replay semantics", () => {
  test("undefined allowlist allows any signer", () => {
    const { allowlist: _drop, ...rest } = base();
    assert.equal(verify(rest).ok, true);
  });
  test("empty allowlist allows nobody", () => {
    assert.equal(verify({ ...base(), allowlist: [] }).reason, "not_allowlisted");
  });
  test("allowlist accepts any iterable, e.g. a Set", () => {
    assert.equal(verify({ ...base(), allowlist: new Set([ADDR_A]) }).ok, true);
  });
  test("seen set is not mutated", () => {
    const seen = new Set<string>(["other0000"]);
    verify({ ...base(), seen });
    assert.deepEqual([...seen], ["other0000"]);
  });
  test("recording the returned nonce blocks a second use", () => {
    const seen = new Set<string>();
    const r1 = verify({ ...base(), seen });
    assert.ok(r1.ok);
    if (r1.ok) seen.add(r1.nonce);
    assert.equal(verify({ ...base(), seen }).reason, "replayed_nonce");
  });
  test("a different nonce in seen does not block", () => {
    assert.equal(verify({ ...base(), seen: new Set(["abc123XYZ78"]) }).ok, true);
  });
});

describe("malformed messages never throw", () => {
  test("garbage, empty, and trailing content", () => {
    const { message } = signed();
    for (const m of ["", "hello", message + "\n", message + "\nURI: x", "\n" + message, message.replace("\n\n", "\n")])
      assert.equal(verify({ ...base(), message: m }).reason, "malformed_message", JSON.stringify(m));
  });
});
