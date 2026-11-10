// Popup: shows the current tab's report and lets you check any text.
// Page content is untrusted, so everything is added with textContent, never as HTML.
"use strict"

const $ = (selector) => document.querySelector(selector)
const ATTACK = { sqli: "SQL injection", xss: "Cross-site scripting" }

function el(tag, props = {}, children = []) {
  const node = document.createElement(tag)
  Object.assign(node, props)
  for (const child of children) if (child !== null && child !== undefined) node.append(child)
  return node
}

function findingList(findings) {
  return findings.slice(0, 4).map((f) =>
    el("div", { className: "finding" }, [
      el("span", { className: "tag", textContent: f.severity }),
      el("span", { className: "tag", textContent: f.location }),
      el("div", { textContent: `${f.rule_id}: ${f.rule_name}` }),
      el("code", { textContent: f.evidence }),
    ]),
  )
}

function verdictBox(target, findings, safeTitle, safeText) {
  target.replaceChildren()
  const bad = findings.length > 0
  target.className = `verdict ${bad ? "bad" : "good"}`
  const top = bad ? findings[0] : null
  target.append(
    el("span", { className: "icon", textContent: bad ? "⛔" : "✅", ariaHidden: "true" }),
    el("div", {}, [
      el("b", { textContent: bad ? `${ATTACK[top.attack] || top.attack} detected` : safeTitle }),
      el("span", { className: "muted", textContent: bad ? "The Hybrid WAF would block this." : safeText }),
      ...(bad ? findingList(findings) : []),
    ]),
  )
}

function renderLinks(state) {
  const box = $("#links")
  box.replaceChildren(el("h2", { textContent: "Links on this page" }))
  if (!state.links) {
    box.append(el("p", { className: "muted", textContent: "Not scanned yet. Reload the page if you installed the extension after opening it." }))
    return
  }
  const { total, flagged } = state.links
  box.append(el("p", { className: "muted", textContent: `Scanned ${total} link${total === 1 ? "" : "s"}: ${flagged.length} dangerous.` }))
  if (flagged.length) {
    box.append(
      el("ul", { className: "links" }, flagged.map((link) =>
        el("li", {}, [
          el("span", { className: "tag", textContent: `${link.rule}` }),
          el("span", { textContent: link.text || "(no text)" }),
          el("code", { textContent: link.href }),
        ]),
      )),
    )
  }
}

function renderGrade(state) {
  const box = $("#grade")
  box.replaceChildren(el("h2", { textContent: "Security headers" }))
  const grade = state.headers
  if (!grade) {
    box.append(el("p", { className: "muted", textContent: "Reload the page to grade the security headers it sent." }))
    return
  }
  box.append(
    el("div", { className: "grade" }, [
      el("div", { className: `letter ${grade.letter}`, textContent: grade.letter, ariaLabel: `Grade ${grade.letter}` }),
      el("div", {}, [
        el("b", { textContent: `${grade.score} / 100` }),
        el("p", { className: "muted", textContent: "How well this site asks the browser to protect you." }),
      ]),
    ]),
    el("ul", { className: "checks" }, grade.results.map((r) =>
      el("li", {}, [
        el("span", { className: r.status, textContent: r.status === "pass" ? "✓" : r.status === "partial" ? "◐" : "✗", ariaLabel: r.status }),
        el("span", {}, [r.title, el("small", { textContent: r.note })]),
      ]),
    )),
  )
}

async function renderPage() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true })
  if (!tab) return
  const state = (await chrome.runtime.sendMessage({ type: "get-state", tabId: tab.id })) || {}
  const url = tab.url || ""
  if (!/^https?:/.test(url)) {
    verdictBox($("#verdict"), [], "Nothing to check here", "Open a website to see its report.")
    $("#links").hidden = true
    $("#grade").hidden = true
    return
  }
  // Checked again here, so the answer is right even if the background worker was asleep.
  const findings = WafEngine.inspectUrl(url).findings
  verdictBox($("#verdict"), findings, "This page's address is clean", "No SQL injection or XSS hidden in the address.")
  renderLinks(state)
  renderGrade(state)
}

function renderCheck() {
  const text = $("#text").value
  const out = $("#check-result")
  out.replaceChildren()
  if (!text.trim()) return
  const asUrl = /^https?:\/\//i.test(text.trim()) ? WafEngine.inspectUrl(text.trim()).findings : []
  const findings = WafEngine.sortFindings([...asUrl, ...WafEngine.scanValue(text, "text")].filter(
    (f, i, all) => all.findIndex((g) => g.rule_id === f.rule_id) === i,
  ))
  const box = el("div")
  verdictBox(box, findings, "No attack found", "The Hybrid WAF would let this through.")
  out.append(box)
  const rounds = WafEngine.decodeRounds(text)
  if (rounds.length) {
    out.append(
      el("div", { className: "card" }, [
        el("h2", { textContent: "Hidden layers the WAF unwrapped" }),
        el("ol", { className: "steps" }, rounds.map((r) => el("li", {}, [el("code", { textContent: r })]))),
      ]),
    )
  }
}

function showView(view) {
  for (const tab of document.querySelectorAll("nav button")) tab.setAttribute("aria-selected", String(tab.dataset.view === view))
  for (const panel of document.querySelectorAll("[data-panel]")) panel.hidden = panel.dataset.panel !== view
  if (view === "check") $("#text").focus()
}

async function setupSettings() {
  const { settings = {} } = await chrome.storage.local.get("settings")
  for (const id of ["highlightLinks", "warnOnClick", "pageBanner"]) {
    const box = document.getElementById(id)
    box.checked = settings[id] !== false
    box.addEventListener("change", async () => {
      const current = (await chrome.storage.local.get("settings")).settings || {}
      await chrome.storage.local.set({ settings: { ...current, [id]: box.checked } })
    })
  }
  $("#rule-count").textContent = String(WafEngine.ruleCount)
}

async function main() {
  for (const tab of document.querySelectorAll("nav button")) tab.addEventListener("click", () => showView(tab.dataset.view))
  $("#text").addEventListener("input", renderCheck)
  await setupSettings()

  // Opened from the right-click menu: show that item in the checker.
  if (new URLSearchParams(location.search).get("view") === "check") {
    document.body.classList.add("window")
    const { pendingCheck } = await chrome.storage.session.get("pendingCheck")
    await chrome.storage.session.remove("pendingCheck")
    $("#text").value = pendingCheck || ""
    showView("check")
    renderCheck()
    $("#verdict").textContent = "Open the extension from the toolbar to see a page report."
    return
  }
  await renderPage()
}

void main()
