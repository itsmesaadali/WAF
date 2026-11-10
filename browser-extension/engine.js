// JavaScript copy of the Hybrid WAF's detection engine (waf-backend/app/detection).
// It runs entirely inside the browser: nothing you visit is sent anywhere.
// test/engine.test.js checks it gives the same answers as the Python WAF.
(function (root) {
  "use strict"

  const MAX_DECODE_ROUNDS = 4
  const MAX_INSPECT_CHARS = 64 * 1024
  const EVIDENCE_LIMIT = 200
  const SEVERITY_ORDER = { medium: 1, high: 2, critical: 3 }

  const UNICODE_ESCAPE = /(?:\\u|%u)([0-9a-fA-F]{4})/g
  const HEX_ESCAPE = /\\x([0-9a-fA-F]{2})/g
  const SQL_BLOCK_COMMENT = /\/\*[\s\S]*?\*\//g
  const WHITESPACE = /\s+/g
  const BASE64_TOKEN = /^[A-Za-z0-9+/_-]{12,}={0,2}$/
  const ZERO_WIDTH = /[​‌‍⁠﻿­]/g
  const CONTROL = /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/g
  const PERCENT_RUN = /(?:%[0-9a-fA-F]{2})+/g
  const NOT_PRINTABLE = /[\p{Cc}\p{Cf}\p{Cs}\p{Co}\p{Cn}\p{Zl}\p{Zp}]/u
  const ODD_SPACE = /\p{Zs}/u

  const utf8 = new TextDecoder("utf-8")
  const utf8Strict = new TextDecoder("utf-8", { fatal: true })

  // Named entities attackers commonly use. Numeric entities are handled in full.
  const ENTITIES = {
    amp: "&", lt: "<", gt: ">", quot: '"', apos: "'", nbsp: " ", colon: ":", semi: ";",
    lpar: "(", rpar: ")", sol: "/", bsol: "\\", tab: "\t", newline: "\n", grave: "`", equals: "=",
    comma: ",", period: ".", excl: "!", quest: "?", num: "#", percnt: "%", plus: "+", lsqb: "[",
    rsqb: "]", lbrack: "[", rbrack: "]", lcub: "{", rcub: "}", lbrace: "{", rbrace: "}", ast: "*",
    lowbar: "_", vert: "|", dollar: "$", commat: "@", hyphen: "-", dash: "-",
  }
  const LEGACY = new Set(["amp", "lt", "gt", "quot", "nbsp"])

  const compiled = (root.WAF_RULES || []).map((rule) => ({ ...rule, regex: new RegExp(rule.pattern) }))

  function unquotePlus(value) {
    return value.replace(/\+/g, " ").replace(PERCENT_RUN, (run) => {
      const bytes = run.match(/%[0-9a-fA-F]{2}/g).map((h) => parseInt(h.slice(1), 16))
      return utf8.decode(Uint8Array.from(bytes))
    })
  }

  function htmlUnescape(value) {
    if (value.indexOf("&") === -1) return value
    return value.replace(/&(#[0-9]+;?|#[xX][0-9a-fA-F]+;?|[A-Za-z][A-Za-z0-9]*;?)/g, (whole, body) => {
      if (body[0] === "#") {
        const hex = body[1] === "x" || body[1] === "X"
        const code = parseInt(body.replace(/[#xX;]/g, ""), hex ? 16 : 10)
        if (!code || code > 0x10ffff || (code >= 0xd800 && code <= 0xdfff)) return "�"
        return String.fromCodePoint(code)
      }
      const semi = body.endsWith(";")
      const name = semi ? body.slice(0, -1) : body
      const key = name.toLowerCase()
      if (semi && ENTITIES[key] !== undefined && (name === key || key === "tab" || key === "newline")) return ENTITIES[key]
      if (!semi && LEGACY.has(name)) return ENTITIES[name]
      return whole
    })
  }

  function decodeOnce(value) {
    let decoded = unquotePlus(value)
    decoded = htmlUnescape(decoded)
    decoded = decoded.replace(UNICODE_ESCAPE, (_, h) => String.fromCharCode(parseInt(h, 16)))
    decoded = decoded.replace(HEX_ESCAPE, (_, h) => String.fromCharCode(parseInt(h, 16)))
    return decoded
  }

  function decodeRounds(value) {
    const rounds = []
    let current = value.slice(0, MAX_INSPECT_CHARS)
    for (let i = 0; i < MAX_DECODE_ROUNDS; i++) {
      const decoded = decodeOnce(current).slice(0, MAX_INSPECT_CHARS)
      if (decoded === current) break
      rounds.push(decoded)
      current = decoded
    }
    return rounds
  }

  function deepDecode(value) {
    const rounds = decodeRounds(value)
    return rounds.length ? rounds[rounds.length - 1] : value.slice(0, MAX_INSPECT_CHARS)
  }

  function clean(value) {
    return deepDecode(value).normalize("NFKC").replace(ZERO_WIDTH, "").replace(CONTROL, "")
  }

  function normalize(value) {
    return clean(value).replace(SQL_BLOCK_COMMENT, " ").replace(WHITESPACE, " ").trim().toLowerCase()
  }

  function compact(value) {
    return clean(value).replace(SQL_BLOCK_COMMENT, "").replace(WHITESPACE, "").toLowerCase()
  }

  function tryBase64(value) {
    const stripped = value.trim()
    if (stripped.length > 8192 || !BASE64_TOKEN.test(stripped)) return null
    const padded = stripped + "=".repeat((4 - (stripped.length % 4)) % 4)
    let text
    try {
      const binary = atob(padded.replace(/-/g, "+").replace(/_/g, "/"))
      text = utf8Strict.decode(Uint8Array.from(binary, (c) => c.charCodeAt(0)))
    } catch {
      return null
    }
    const chars = Array.from(text)
    if (!chars.length) return null
    const printable = chars.filter((c) => /\s/.test(c) || !(NOT_PRINTABLE.test(c) || (ODD_SPACE.test(c) && c !== " "))).length
    return printable / chars.length > 0.95 ? text : null
  }

  function evidence(text, start, end) {
    return text.slice(Math.max(0, start - 30), Math.min(text.length, end + 30)).slice(0, EVIDENCE_LIMIT)
  }

  /** Check one value and return a finding for each rule that matches. */
  function scanValue(value, location) {
    if (!value) return []
    const variants = [value]
    const decoded = tryBase64(value) || tryBase64(deepDecode(value))
    if (decoded) variants.push(decoded)
    const findings = []
    const seen = new Set()
    for (const variant of variants) {
      const normal = normalize(variant)
      const squashed = compact(variant)
      for (const rule of compiled) {
        if (seen.has(rule.id)) continue
        const text = rule.form === "compact" ? squashed : normal
        const found = rule.regex.exec(text)
        if (found) {
          seen.add(rule.id)
          findings.push({
            rule_id: rule.id, rule_name: rule.name, attack: rule.attack, severity: rule.severity,
            location, evidence: evidence(text, found.index, found.index + found[0].length),
          })
        }
      }
    }
    return findings
  }

  /** Same splitting as Python's parse_qsl(keep_blank_values=True). */
  function parseQuery(query) {
    return query.split("&").filter(Boolean).map((piece) => {
      const at = piece.indexOf("=")
      return at === -1 ? [unquotePlus(piece), ""] : [unquotePlus(piece.slice(0, at)), unquotePlus(piece.slice(at + 1))]
    })
  }

  function sortFindings(findings) {
    return findings.sort((a, b) => (SEVERITY_ORDER[b.severity] || 0) - (SEVERITY_ORDER[a.severity] || 0))
  }

  /** Check a web address the way the WAF checks a request, plus the #fragment that never reaches a server. */
  function inspectUrl(href) {
    let url
    try {
      url = new URL(href)
    } catch {
      return { ok: false, findings: [] }
    }
    if (url.protocol !== "http:" && url.protocol !== "https:") return { ok: false, findings: [] }
    const findings = []
    const seen = new Set()
    const add = (items) => {
      for (const item of items) {
        const key = item.rule_id + "|" + item.location
        if (!seen.has(key)) {
          seen.add(key)
          findings.push(item)
        }
      }
    }
    add(scanValue(url.pathname, "path"))
    const query = url.search.slice(1)
    if (query) {
      const pairs = parseQuery(query)
      add(scanValue(query, "query"))
      for (const [key, value] of pairs) {
        add(scanValue(key, "query"))
        add(scanValue(value, "query"))
      }
      if (pairs.length > 1) add(scanValue(pairs.map((p) => p[1]).join(" "), "query"))
    }
    const fragment = url.hash.slice(1)
    if (fragment) add(scanValue(fragment, "fragment"))
    return { ok: true, findings: sortFindings(findings) }
  }

  const api = { decodeRounds, deepDecode, normalize, compact, tryBase64, scanValue, inspectUrl, parseQuery, sortFindings, ruleCount: compiled.length }
  root.WafEngine = api
  if (typeof module !== "undefined") module.exports = api
})(globalThis)
