import * as assert from "node:assert/strict";
import { test } from "node:test";
import { ScanState, statusText } from "../state";

test("a first scan failure stays an error across renders and retries", () => {
  const state = new ScanState();
  state.fail(state.begin(), "engine exited 2");
  assert.match(statusText([state]), /scan error/);
  assert.equal(state.hasResult, false);
  const retry = state.begin();
  assert.match(statusText([state]), /scan error/);
  state.complete(retry, [0, 0, 0]);
  assert.doesNotMatch(statusText([state]), /scan error|not checked|stale/);
  assert.equal(state.error, "");
});

test("a failed refresh preserves counts and marks the previous result stale", () => {
  const state = new ScanState();
  state.complete(state.begin(), [2, 1, 0]);
  state.fail(state.begin(), "timed out");
  assert.deepEqual(state.counts, [2, 1, 0]);
  assert.equal(state.stale, true);
  assert.equal(state.hasResult, true);
  assert.match(statusText([state]), /scan error/);
});

test("edits invalidate results and an in-flight scan cannot replace them", () => {
  const state = new ScanState();
  state.complete(state.begin(), [1, 0, 0]);
  const token = state.begin();
  state.invalidate();
  assert.equal(state.complete(token, [0, 0, 0]), false);
  state.running = false;
  assert.match(statusText([state]), /stale results/);
  assert.deepEqual(state.counts, [1, 0, 0]);
  state.complete(state.begin(), [0, 0, 0]);
  assert.equal(state.stale, false);
});

test("success in another workspace does not hide an error or stale result", () => {
  const a = new ScanState(), b = new ScanState();
  a.fail(a.begin(), "missing CLI");
  b.complete(b.begin(), [0, 0, 0]);
  assert.match(statusText([a, b]), /scan error/);
  a.complete(a.begin(), [0, 0, 0]);
  b.invalidate();
  assert.match(statusText([a, b]), /stale results/);
});

test("never checked and running states cannot resemble a clean scan", () => {
  assert.match(statusText([]), /not checked/);
  const state = new ScanState();
  assert.match(statusText([state]), /not checked/);
  state.begin();
  assert.match(statusText([state]), /checking/);
});
