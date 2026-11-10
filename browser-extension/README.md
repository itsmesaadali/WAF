# WAF Link Guard (Chrome extension)

A Chrome extension that brings the Hybrid WAF's detection to ordinary users. The WAF protects a website from attackers. Link Guard protects a person from booby-trapped links, which is how reflected XSS usually reaches its victim.

## What it does

| Feature | How it works |
|---|---|
| Page check | The toolbar badge shows **!** when the address you're on hides SQL injection or XSS, a number when the page has dangerous links, and **✓** when nothing was found |
| Warning banner | A red banner warns you not to type passwords on a page whose address carries an attack |
| Link outlines | Dangerous links get a red dashed outline, and hovering one says which rule matched |
| Click warning | Clicking a dangerous link asks first, and you can still open it if you choose |
| Security header grade | Grades the site from A to F on HTTPS, HSTS, CSP, clickjacking protection and more, using headers the browser already received |
| Check text | Paste any link, message or form value, and see the verdict and each decoding layer |
| Right-click menu | **Check this link** on any link, or check selected text |

It uses the same 26 signatures and decoding steps as the WAF. Automated tests compare its answers with the Python WAF on 117 test values.

It can catch something the WAF can't: attacks in the `#fragment` part of an address. Browsers never send that part to the server, so no WAF ever sees it.

## Privacy

Everything runs inside your browser. Addresses, page content and headers are never sent anywhere, and the extension makes no network requests of its own.

Permissions:
- **Read pages and links:** to outline dangerous links.
- **webRequest:** to read response headers for the grade. It's read-only, so nothing is changed or blocked.
- **tabs:** to read the current tab's address.
- **storage** and **contextMenus:** for settings and the right-click menu.

## Install it (no Chrome Web Store needed)

1. Open `chrome://extensions` in Chrome or Edge (`edge://extensions`).
2. Turn on **Developer mode** (top right).
3. Click **Load unpacked** and choose this `browser-extension` folder.
4. Pin **WAF Link Guard** from the puzzle-piece menu so the badge is visible.

After changing any file, click the reload icon on the extension's card.

## Demo for the viva

1. Start the project (`.\scripts\start-all.ps1`).
2. Open http://localhost:8000/link-guard-demo.html, a pretend inbox served through the WAF.
3. Dangerous links have red outlines, and the badge shows how many there are.
4. Click **"Check out this discount!"**. Link Guard warns you first.
5. Click **Open anyway**, and the WAF blocks it with a 403. That's two layers of defence.
6. On the blocked page, Link Guard's red banner explains the address carries an attack.
7. Click the extension icon to see the security header grade, then try **Check text**.
8. Open any real site, such as your own, to see its header grade.

## Keeping the rules in sync

`rules.js` is generated from the WAF's Python signatures. After changing signatures, run:

```powershell
py scripts\export-extension-rules.py
node --test browser-extension/test/engine.test.js browser-extension/test/grade.test.js
```

The export also records the Python WAF's answers, and the test fails if the JavaScript engine disagrees with any of them.

## Files

| File | Purpose |
|---|---|
| `manifest.json` | Extension settings and permissions (Manifest V3) |
| `rules.js` | Signatures generated from the WAF |
| `engine.js` | JavaScript copy of the WAF's decoding and matching |
| `grade.js` | Security header grading |
| `background.js` | Badge, header grading and right-click menu |
| `content.js` | Link outlines, click warnings and the page banner |
| `popup.html`, `popup.js`, `popup.css` | The toolbar popup, in light and dark themes |
| `test/` | Parity and grading tests, plus `popup-harness.html` for previewing the popup outside Chrome |

## Limits

- It checks addresses and links, not the scripts a page already contains.
- Like the WAF, its signatures can miss new attack techniques.
- The header grade covers common headers only. It's a quick check, not a full security audit.
- Publishing to the Chrome Web Store would need a developer account and Google's review. Loading it unpacked is enough for the project.
