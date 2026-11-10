// Runs inside web pages: marks dangerous links, warns before they open, and warns when the
// page's own address carries an attack (the usual way reflected XSS reaches a victim).
(function () {
  "use strict"
  if (window.__wafLinkGuard) return
  window.__wafLinkGuard = true

  const MAX_LINKS = 3000
  const cache = new Map()
  let settings = { highlightLinks: true, warnOnClick: true, pageBanner: true }

  const describe = (finding) =>
    `${finding.attack === "sqli" ? "SQL injection" : "Cross-site scripting"} (${finding.rule_id}: ${finding.rule_name})`

  function check(href) {
    if (!cache.has(href)) cache.set(href, WafEngine.inspectUrl(href).findings)
    return cache.get(href)
  }

  // Warnings live in a shadow root, so the page's styles and scripts can't change them.
  function overlayHost() {
    const host = document.createElement("waf-link-guard")
    host.style.all = "initial"
    const shadow = host.attachShadow({ mode: "closed" })
    const style = document.createElement("style")
    style.textContent = `
      :host { all: initial; }
      * { box-sizing: border-box; font-family: system-ui, -apple-system, "Segoe UI", sans-serif; }
      .banner { position: fixed; inset: 0 0 auto 0; z-index: 2147483647; display: flex; gap: 12px; align-items: flex-start;
        padding: 12px 16px; background: #b3261e; color: #fff; font-size: 14px; line-height: 1.4; box-shadow: 0 2px 12px rgba(0,0,0,.3); }
      .banner b { display: block; font-size: 15px; }
      .banner code, .card code { font-family: ui-monospace, Consolas, monospace; font-size: 12px; word-break: break-all; }
      .grow { flex: 1; min-width: 0; }
      .backdrop { position: fixed; inset: 0; z-index: 2147483647; background: rgba(0,0,0,.55); display: flex; align-items: center; justify-content: center; padding: 16px; }
      .card { max-width: 480px; width: 100%; background: #fff; color: #1b1b1b; border-radius: 12px; padding: 20px; box-shadow: 0 10px 40px rgba(0,0,0,.35); }
      .card h2 { margin: 0 0 8px; font-size: 18px; color: #b3261e; }
      .card p { margin: 0 0 10px; font-size: 14px; line-height: 1.45; }
      .card ul { margin: 0 0 12px; padding-left: 18px; font-size: 13px; }
      .card .url { background: #f3f3f3; border-radius: 6px; padding: 8px; margin-bottom: 12px; max-height: 90px; overflow: auto; }
      .row { display: flex; gap: 8px; justify-content: flex-end; flex-wrap: wrap; }
      button { font: inherit; font-size: 14px; border-radius: 8px; padding: 8px 14px; cursor: pointer; border: 1px solid transparent; }
      .primary { background: #1b1b1b; color: #fff; }
      .ghost { background: transparent; color: inherit; border-color: currentColor; }
      .danger-link { background: transparent; border: 0; color: #b3261e; text-decoration: underline; padding: 8px 4px; }
      @media (prefers-color-scheme: dark) {
        .card { background: #1f1f1f; color: #eee; }
        .card .url { background: #2b2b2b; }
        .card h2, .danger-link { color: #ff8a80; }
        .primary { background: #eee; color: #111; }
      }`
    shadow.appendChild(style)
    document.documentElement.appendChild(host)
    return { host, shadow }
  }

  function el(tag, props = {}, children = []) {
    const node = document.createElement(tag)
    Object.assign(node, props)
    for (const child of children) node.append(child)
    return node
  }

  function showPageBanner(findings) {
    const { host, shadow } = overlayHost()
    const close = el("button", { className: "ghost", textContent: "Dismiss" })
    close.addEventListener("click", () => host.remove())
    shadow.append(
      el("div", { className: "banner", role: "alert" }, [
        el("div", { className: "grow" }, [
          el("b", { textContent: "Warning: this page's address contains a hidden attack" }),
          `WAF Link Guard found ${describe(findings[0])}. Someone may have sent you this link to attack your account on this site. Don't type passwords or personal details here. `,
          el("code", { textContent: findings[0].evidence }),
        ]),
        close,
      ]),
    )
  }

  function confirmOpen(link, findings) {
    const { host, shadow } = overlayHost()
    const back = el("button", { className: "primary", textContent: "Stay safe, don't open it" })
    const anyway = el("button", { className: "danger-link", textContent: "Open anyway" })
    const closeAll = () => host.remove()
    back.addEventListener("click", closeAll)
    anyway.addEventListener("click", () => {
      closeAll()
      if (link.target === "_blank") window.open(link.href, "_blank", "noopener")
      else window.location.assign(link.href)
    })
    const backdrop = el("div", { className: "backdrop" }, [
      el("div", { className: "card", role: "alertdialog", ariaModal: "true", ariaLabel: "Dangerous link" }, [
        el("h2", { textContent: "This link looks like an attack" }),
        el("p", { textContent: "WAF Link Guard found attack code hidden in this link's address. Opening it could run someone else's code on the site, or tamper with its database." }),
        el("ul", {}, findings.slice(0, 3).map((f) => el("li", { textContent: describe(f) }))),
        el("div", { className: "url" }, [el("code", { textContent: link.href })]),
        el("div", { className: "row" }, [anyway, back]),
      ]),
    ])
    backdrop.addEventListener("click", (event) => { if (event.target === backdrop) closeAll() })
    shadow.addEventListener("keydown", (event) => { if (event.key === "Escape") closeAll() })
    shadow.append(backdrop)
    back.focus()
  }

  function mark(link, findings) {
    if (!settings.highlightLinks) return
    link.dataset.wafLinkGuard = "danger"
    link.style.outline = "2px dashed #d03b3b"
    link.style.outlineOffset = "2px"
    link.title = `⚠ WAF Link Guard: ${describe(findings[0])}`
  }

  function unmarkAll() {
    for (const link of document.querySelectorAll("a[data-waf-link-guard]")) {
      link.style.outline = ""
      link.style.outlineOffset = ""
      link.removeAttribute("title")
      delete link.dataset.wafLinkGuard
    }
  }

  function scanLinks() {
    const links = Array.from(document.links).slice(0, MAX_LINKS)
    const flagged = []
    for (const link of links) {
      const findings = check(link.href)
      if (findings.length) {
        mark(link, findings)
        flagged.push({ href: link.href.slice(0, 500), text: (link.textContent || "").trim().slice(0, 80), rule: findings[0].rule_id, attack: findings[0].attack })
      }
    }
    try {
      chrome.runtime.sendMessage({ type: "links", total: links.length, flagged })
    } catch {
      // The extension was reloaded; this old copy of the script just stops reporting.
    }
  }

  document.addEventListener(
    "click",
    (event) => {
      if (!settings.warnOnClick || event.button !== 0) return
      const link = event.target instanceof Element ? event.target.closest("a[href]") : null
      if (!link) return
      const findings = check(link.href)
      if (!findings.length) return
      event.preventDefault()
      event.stopImmediatePropagation()
      confirmOpen(link, findings)
    },
    true,
  )

  let pending = null
  const observer = new MutationObserver(() => {
    if (pending) return
    pending = setTimeout(() => {
      pending = null
      scanLinks()
    }, 800)
  })

  chrome.storage.local.get("settings").then((saved) => {
    settings = { ...settings, ...(saved.settings || {}) }
    const page = WafEngine.inspectUrl(location.href).findings
    if (page.length && settings.pageBanner) showPageBanner(page)
    scanLinks()
    observer.observe(document.documentElement, { childList: true, subtree: true })
  })

  chrome.storage.onChanged.addListener((changes, area) => {
    if (area !== "local" || !changes.settings) return
    settings = { ...settings, ...changes.settings.newValue }
    unmarkAll()
    scanLinks()
  })
})()
