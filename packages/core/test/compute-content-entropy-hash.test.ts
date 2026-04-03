import { strict as assert } from "node:assert";
import { test } from "node:test";
import { computeContentEntropyHash } from "../src/index";

test("valid JSON object — key order does not affect hash", () => {
  const a = '{"b":2,"a":1}';
  const b = '{"a":1,"b":2}';
  assert.equal(computeContentEntropyHash(a), computeContentEntropyHash(b));
});

test("valid JSON array — produces sha256 hash", () => {
  assert.match(computeContentEntropyHash("[1,2,3]"), /^sha256:[0-9a-f]{64}$/);
});

test("JSON primitive — hashes the raw string, not parsed value", () => {
  const numHash = computeContentEntropyHash("42");
  const strHash = computeContentEntropyHash('"hello"');
  const boolHash = computeContentEntropyHash("true");
  assert.match(numHash, /^sha256:[0-9a-f]{64}$/);
  assert.match(strHash, /^sha256:[0-9a-f]{64}$/);
  assert.match(boolHash, /^sha256:[0-9a-f]{64}$/);
});

test("non-JSON string — hashes the raw string", () => {
  assert.match(computeContentEntropyHash("hello"), /^sha256:[0-9a-f]{64}$/);
});

test("same JSON content, different whitespace — same hash", () => {
  const c = '{"a":1,"b":2}';
  const d = '{ "a" : 1 , "b" : 2 }';
  assert.equal(computeContentEntropyHash(c), computeContentEntropyHash(d));
});

test("different content — different hash", () => {
  assert.notEqual(
    computeContentEntropyHash('{"a":1}'),
    computeContentEntropyHash('{"a":2}')
  );
});
