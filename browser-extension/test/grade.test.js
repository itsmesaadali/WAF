const test = require("node:test")
const assert = require("node:assert")
const { grade } = require("../grade.js")

test("a well-configured HTTPS site gets an A", () => {
  const result = grade("https://shop.example/", {
    "strict-transport-security": "max-age=31536000",
    "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
    "x-content-type-options": "nosniff",
    "referrer-policy": "strict-origin-when-cross-origin",
    "permissions-policy": "camera=()",
  })
  assert.strictEqual(result.score, 100)
  assert.strictEqual(result.letter, "A")
})

test("plain HTTP with no headers and a version leak gets an F", () => {
  const result = grade("http://shop.example/", { server: "Apache/2.4.1", "x-powered-by": "PHP/7.0" })
  assert.strictEqual(result.letter, "F")
  assert.ok(result.results.every((r) => r.status === "fail"))
})

test("a CSP that allows inline scripts only earns half its points", () => {
  const result = grade("https://shop.example/", { "content-security-policy": "script-src 'self' 'unsafe-inline'" })
  const csp = result.results.find((r) => r.id === "csp")
  assert.strictEqual(csp.status, "partial")
  assert.strictEqual(csp.earned, 10)
})
