// Grades a page's security headers from what the browser already received. No extra requests.
(function (root) {
  "use strict"

  const csp = (h) => h["content-security-policy"] || ""

  const CHECKS = [
    {
      id: "https", points: 20, title: "Encrypted connection (HTTPS)",
      why: "Without HTTPS, anyone on the same Wi-Fi can read or change the page.",
      test: (url) => url.startsWith("https://"),
    },
    {
      id: "hsts", points: 15, title: "Always use HTTPS (Strict-Transport-Security)",
      why: "Stops attackers from downgrading you to an unencrypted connection.",
      test: (url, h) => url.startsWith("https://") && /max-age=\s*"?[1-9]/i.test(h["strict-transport-security"] || ""),
    },
    {
      id: "csp", points: 20, title: "Content Security Policy",
      why: "The browser's own XSS defence: it limits which scripts may run.",
      test: (url, h) => Boolean(csp(h)),
      partial: (url, h) => /script-src[^;]*'unsafe-inline'/i.test(csp(h)) || !/script-src|default-src/i.test(csp(h)),
      partialNote: "Present, but it still allows inline scripts, so XSS protection is weaker.",
    },
    {
      id: "frames", points: 15, title: "Clickjacking protection",
      why: "Stops other sites hiding this page in an invisible frame to trick your clicks.",
      test: (url, h) => /deny|sameorigin/i.test(h["x-frame-options"] || "") || /frame-ancestors/i.test(csp(h)),
    },
    {
      id: "nosniff", points: 10, title: "No content sniffing (X-Content-Type-Options)",
      why: "Stops the browser treating uploaded files as scripts.",
      test: (url, h) => /nosniff/i.test(h["x-content-type-options"] || ""),
    },
    {
      id: "referrer", points: 10, title: "Referrer-Policy",
      why: "Limits how much of your address leaks to other sites.",
      test: (url, h) => Boolean(h["referrer-policy"]) && !/unsafe-url/i.test(h["referrer-policy"]),
    },
    {
      id: "permissions", points: 5, title: "Permissions-Policy",
      why: "Switches off camera, microphone and other features the site doesn't use.",
      test: (url, h) => Boolean(h["permissions-policy"]),
    },
    {
      id: "quiet", points: 5, title: "Hides server software versions",
      why: "Version numbers help attackers pick known exploits.",
      test: (url, h) => !h["x-powered-by"] && !/\d/.test(h["server"] || ""),
    },
  ]

  function letter(score) {
    if (score >= 90) return "A"
    if (score >= 75) return "B"
    if (score >= 60) return "C"
    if (score >= 40) return "D"
    return "F"
  }

  function grade(url, headers) {
    let score = 0
    const results = CHECKS.map((check) => {
      let status = check.test(url, headers) ? "pass" : "fail"
      let note = check.why
      let earned = status === "pass" ? check.points : 0
      if (status === "pass" && check.partial && check.partial(url, headers)) {
        status = "partial"
        earned = Math.round(check.points / 2)
        note = check.partialNote
      }
      score += earned
      return { id: check.id, title: check.title, status, note, points: check.points, earned }
    })
    return { score, letter: letter(score), results, checkedAt: Date.now() }
  }

  const api = { grade, letter, CHECKS }
  root.WafGrade = api
  if (typeof module !== "undefined") module.exports = api
})(globalThis)
