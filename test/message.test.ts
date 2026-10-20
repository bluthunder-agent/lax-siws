import { test } from "node:test";
import assert from "node:assert/strict";
import { createMessage, parseMessage, SiwsFormatError } from "../src/index.ts";
import { ADDR_A, params } from "./helpers.ts";

test("exact canonical format", () => {
  assert.equal(
    createMessage(params()),
    [
      "app.example.com wants you to sign in with your Solana account:",
      ADDR_A,
      "",
      "Sign in to Example",
      "",
      "Nonce: abc123XYZ789",
      "Issued At: 2026-10-20T12:00:00.000Z",
      "Expiration Time: 2026-10-20T12:10:00.000Z",
    ].join("\n"),
  );
});

test("round trip with and without statement", () => {
  for (const p of [params(), (({ statement: _s, ...r }) => r)(params())])
    assert.deepEqual(parseMessage(createMessage(p)), p);
});

test("createMessage rejects invalid params", () => {
  const bad = [
    { domain: "" },
    { domain: "a b.com" },
    { domain: "x.com/path" },
    { address: "notbase58!" },
    { address: "1111" },
    { statement: "two\nlines" },
    { statement: "" },
    { nonce: "short" },
    { nonce: "has space 123" },
    { issuedAt: "2026-10-20 12:00:00" },
    { issuedAt: "2026-13-40T12:00:00.000Z" },
    { expirationTime: "2026-10-20T12:00:00.000Z" },
    { expirationTime: "2026-10-20T11:00:00.000Z" },
  ];
  for (const over of bad) assert.throws(() => createMessage(params(over)), SiwsFormatError, JSON.stringify(over));
});

test("parse refuses reordered fields", () => {
  const lines = createMessage(params()).split("\n");
  [lines[5], lines[6]] = [lines[6]!, lines[5]!];
  assert.throws(() => parseMessage(lines.join("\n")), SiwsFormatError);
});

test("parse refuses CRLF and extra spaces", () => {
  const m = createMessage(params());
  assert.throws(() => parseMessage(m.replace(/\n/g, "\r\n")), SiwsFormatError);
  assert.throws(() => parseMessage(m.replace("Nonce: ", "Nonce:  ")), SiwsFormatError);
});
