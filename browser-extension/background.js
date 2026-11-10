// Background worker: checks each tab's address, grades security headers, keeps the badge
// up to date and handles the right-click menu. Everything stays on this device.
importScripts("rules.js", "engine.js", "grade.js")

const DEFAULT_SETTINGS = { highlightLinks: true, warnOnClick: true, pageBanner: true }
const COLORS = { danger: "#d03b3b", warning: "#c2570c", good: "#0a7f0a" }

const key = (tabId) => `tab:${tabId}`

async function getState(tabId) {
  const saved = await chrome.storage.session.get(key(tabId))
  return saved[key(tabId)] || {}
}

async function setState(tabId, update) {
  const state = { ...(await getState(tabId)), ...update }
  await chrome.storage.session.set({ [key(tabId)]: state })
  await updateBadge(tabId, state)
  return state
}

async function updateBadge(tabId, state) {
  const pageHits = state.page?.findings?.length || 0
  const badLinks = state.links?.flagged?.length || 0
  let text = ""
  let color = COLORS.good
  let title = "WAF Link Guard: nothing suspicious found"
  if (pageHits) {
    text = "!"
    color = COLORS.danger
    title = "WAF Link Guard: this page's address contains an attack"
  } else if (badLinks) {
    text = String(Math.min(badLinks, 99))
    color = COLORS.warning
    title = `WAF Link Guard: ${badLinks} dangerous link${badLinks === 1 ? "" : "s"} on this page`
  } else if (state.page?.checkable) {
    text = "✓"
  }
  try {
    await chrome.action.setBadgeText({ tabId, text })
    await chrome.action.setBadgeBackgroundColor({ tabId, color })
    if (chrome.action.setBadgeTextColor) await chrome.action.setBadgeTextColor({ tabId, color: "#ffffff" })
    await chrome.action.setTitle({ tabId, title })
  } catch {
    // The tab closed before the badge could be set.
  }
}

function checkPage(url) {
  const result = WafEngine.inspectUrl(url)
  return { url, checkable: result.ok, findings: result.findings }
}

chrome.runtime.onInstalled.addListener(async () => {
  const current = await chrome.storage.local.get("settings")
  await chrome.storage.local.set({ settings: { ...DEFAULT_SETTINGS, ...(current.settings || {}) } })
  chrome.contextMenus.removeAll(() => {
    chrome.contextMenus.create({ id: "check-link", title: "Check this link with WAF Link Guard", contexts: ["link"] })
    chrome.contextMenus.create({ id: "check-text", title: "Check “%s” for attacks", contexts: ["selection"] })
  })
})

// Response headers of each page load, for the security grade. They are only read, never changed.
chrome.webRequest.onHeadersReceived.addListener(
  (details) => {
    if (details.tabId < 0) return
    const headers = {}
    for (const header of details.responseHeaders || []) headers[header.name.toLowerCase()] = header.value || ""
    void setState(details.tabId, { headers: { url: details.url, ...WafGrade.grade(details.url, headers) } })
  },
  { urls: ["http://*/*", "https://*/*"], types: ["main_frame"] },
  ["responseHeaders"],
)

chrome.tabs.onUpdated.addListener(async (tabId, change, tab) => {
  if (!change.url && change.status !== "loading") return
  const url = change.url || tab.url
  if (!url) return
  const state = await getState(tabId)
  if (state.page?.url === url && !change.url) return
  // A new address starts a fresh report, but headers for that same address are kept.
  const headers = state.headers && state.headers.url === url ? state.headers : undefined
  await chrome.storage.session.set({ [key(tabId)]: { headers } })
  await setState(tabId, { page: checkPage(url) })
})

chrome.tabs.onRemoved.addListener((tabId) => void chrome.storage.session.remove(key(tabId)))

chrome.runtime.onMessage.addListener((message, sender, reply) => {
  if (message?.type === "links" && sender.tab?.id !== undefined) {
    void setState(sender.tab.id, { links: { total: message.total, flagged: message.flagged.slice(0, 50) } })
  } else if (message?.type === "get-state") {
    getState(message.tabId).then(reply)
    return true
  }
  return false
})

chrome.contextMenus.onClicked.addListener(async (info) => {
  const text = info.menuItemId === "check-link" ? info.linkUrl : info.selectionText
  if (!text) return
  await chrome.storage.session.set({ pendingCheck: text.slice(0, 8000) })
  await chrome.windows.create({ url: "popup.html?view=check", type: "popup", width: 420, height: 640 })
})
