// Proves the extension's JavaScript engine agrees with the Python WAF.
// Expected answers come from scripts/export-extension-rules.py.
const test = require("node:test")
const assert = require("node:assert")
const path = require("node:path")

require(path.join(__dirname, "..", "rules.js"))
const engine = require(path.join(__dirname, "..", "engine.js"))
const cases = require("./parity-cases.json")

test("loads every WAF rule", () => {
  assert.strictEqual(engine.ruleCount, globalThis.WAF_RULES.length)
  assert.ok(engine.ruleCount >= 26)
})

test("matches the Python WAF on every shared test value", () => {
  const differences = []
  for (const { value, rules } of cases) {
    const got = engine.scanValue(value, "test").map((f) => f.rule_id).sort()
    if (JSON.stringify(got) !== JSON.stringify(rules)) differences.push({ value, python: rules, javascript: got })
  }
  assert.deepStrictEqual(differences, [])
})

test("flags attacks hidden in a link's address", () => {
  const hit = engine.inspectUrl("https://shop.example/search?q=%3Cscript%3Ealert(document.cookie)%3C%2Fscript%3E")
  assert.ok(hit.findings.some((f) => f.attack === "xss"))
  const fragment = engine.inspectUrl("https://shop.example/#<img src=x onerror=alert(1)>")
  assert.ok(fragment.findings.some((f) => f.location === "fragment"))
  const sqli = engine.inspectUrl("http://shop.example/item?id=1%20UNION%20SELECT%20password%20FROM%20users")
  assert.strictEqual(sqli.findings[0].attack, "sqli")
})

test("leaves ordinary links alone", () => {
  for (const href of [
    "https://www.google.com/search?q=how+to+cook+rice&hl=en",
    "https://github.com/user/repo/pull/12#issuecomment-123",
    "https://shop.example/products?category=books&sort=price&page=2",
    "https://en.wikipedia.org/wiki/SQL_injection",
    "https://example.com/?utm_source=newsletter&utm_campaign=nov",
  ]) {
    assert.deepStrictEqual(engine.inspectUrl(href).findings, [], href)
  }
})

test("ignores non-web addresses such as javascript:void(0) buttons", () => {
  assert.strictEqual(engine.inspectUrl("javascript:void(0)").ok, false)
  assert.strictEqual(engine.inspectUrl("mailto:a@b.c").ok, false)
})

test("shows decoding rounds for double-encoded text", () => {
  assert.deepStrictEqual(engine.decodeRounds("%253Cb%253E"), ["%3Cb%3E", "<b>"])
})
