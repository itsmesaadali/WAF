import assert from "node:assert/strict";
import { after, before, test } from "node:test";
import { createApp } from "../src/app.js";

const SECRET = "unit-test-secret";
let server;
let base;

before(async () => {
  server = createApp({ secret: SECRET }).listen(0, "127.0.0.1");
  await new Promise((resolve) => server.once("listening", resolve));
  base = `http://127.0.0.1:${server.address().port}`;
});

after(() => server.close());

test("refuses to start without a shared secret", () => {
  assert.throws(() => createApp({ secret: "" }), /WAF_SHARED_SECRET/);
});

test("direct request without the secret is refused", async () => {
  const res = await fetch(`${base}/`);
  assert.equal(res.status, 403);
});

test("direct request with a wrong secret is refused", async () => {
  const res = await fetch(`${base}/api/products`, { headers: { "x-waf-secret": "wrong" } });
  assert.equal(res.status, 403);
});

test("static files are also protected", async () => {
  const res = await fetch(`${base}/styles.css`);
  assert.equal(res.status, 403);
});

test("request with the correct secret is served", async () => {
  const res = await fetch(`${base}/api/products`, { headers: { "x-waf-secret": SECRET } });
  assert.equal(res.status, 200);
  assert.equal((await res.json()).items.length, 5);
});

test("search output is escaped", async () => {
  const res = await fetch(`${base}/products?q=${encodeURIComponent("<b>")}`, { headers: { "x-waf-secret": SECRET } });
  assert.match(await res.text(), /&lt;b&gt;/);
});

test("order API validates input", async () => {
  const res = await fetch(`${base}/api/orders`, {
    method: "POST",
    headers: { "x-waf-secret": SECRET, "content-type": "application/json" },
    body: JSON.stringify({ productId: 999 }),
  });
  assert.equal(res.status, 400);
});
