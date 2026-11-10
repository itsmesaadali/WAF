/**
 * Evasion tricks attackers use to hide a payload from simple filters. The Attack lab applies
 * them so you can see whether the WAF's decoding still recognises the attack.
 */
const bytes = (text: string) => Array.from(new TextEncoder().encode(text))
const hex = (n: number) => n.toString(16).toUpperCase().padStart(2, "0")

export type Disguise = { id: string; label: string; hint: string; apply: (text: string) => string }

export const DISGUISES: Disguise[] = [
  {
    id: "url",
    label: "URL encode",
    hint: "Every character becomes %XX",
    apply: (t) => bytes(t).map((b) => `%${hex(b)}`).join(""),
  },
  {
    id: "double",
    label: "Double encode",
    hint: "Encode the % signs again, so one decode isn't enough",
    apply: (t) => bytes(t).map((b) => `%25${hex(b)}`).join(""),
  },
  {
    id: "entities",
    label: "HTML entities",
    hint: "Characters written as &#NN;",
    apply: (t) => Array.from(t).map((c) => `&#${c.codePointAt(0)};`).join(""),
  },
  {
    id: "unicode",
    label: "\\u escapes",
    hint: "JavaScript-style \\u00NN escapes",
    apply: (t) => Array.from(t).map((c) => `\\u${(c.codePointAt(0) ?? 0).toString(16).padStart(4, "0")}`).join(""),
  },
  {
    id: "base64",
    label: "Base64",
    hint: "The whole payload wrapped in base64",
    apply: (t) => btoa(String.fromCharCode(...bytes(t))),
  },
  {
    id: "comments",
    label: "Spaces → /**/",
    hint: "SQL comments instead of spaces",
    apply: (t) => t.replace(/ /g, "/**/"),
  },
  {
    id: "case",
    label: "MiXeD cAsE",
    hint: "Alternating letter case",
    apply: (t) => Array.from(t).map((c, i) => (i % 2 ? c.toLowerCase() : c.toUpperCase())).join(""),
  },
  {
    id: "fullwidth",
    label: "Ｆｕｌｌ-width",
    hint: "Look-alike Unicode letters",
    apply: (t) => Array.from(t).map((c) => {
      const code = c.charCodeAt(0)
      return code > 0x20 && code < 0x7f ? String.fromCharCode(code + 0xfee0) : c
    }).join(""),
  },
  {
    id: "zerowidth",
    label: "Zero-width",
    hint: "Invisible characters between letters",
    apply: (t) => Array.from(t).join("​"),
  },
]
