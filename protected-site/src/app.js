import crypto from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";
import express from "express";

const here = path.dirname(fileURLToPath(import.meta.url));

// In-memory demo data only. There is no real personal data on this site.
const PRODUCTS = [
  { id: 1, name: "Security Handbook", category: "books", price: 25 },
  { id: 2, name: "Hardware Key", category: "devices", price: 49 },
  { id: 3, name: "Network Lab Kit", category: "devices", price: 120 },
  { id: 4, name: "Cryptography Primer", category: "books", price: 32 },
  { id: 5, name: "Incident Response Cards", category: "training", price: 15 },
];

function safeEqual(a, b) {
  const left = crypto.createHash("sha256").update(a).digest();
  const right = crypto.createHash("sha256").update(b).digest();
  return crypto.timingSafeEqual(left, right);
}

/** Refuses every request that did not come through the WAF. */
export function requireWaf(secret) {
  return (req, res, next) => {
    const provided = req.get("x-waf-secret");
    if (provided && safeEqual(provided, secret)) return next();
    res
      .status(403)
      .type("text/plain")
      .send("Direct access is not allowed. This website only accepts traffic through the WAF.");
  };
}

function escapeHtml(value) {
  return String(value).replace(
    /[&<>"']/g,
    (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c],
  );
}

function page(title, body) {
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(title)} | SecureShop</title><link rel="stylesheet" href="/styles.css"></head>
<body><header><a class="brand" href="/">SecureShop</a><nav>
<a href="/">Home</a><a href="/products">Products</a><a href="/contact">Contact</a></nav></header>
<main>${body}</main><footer>Authorized test website for the Hybrid WAF project. All data is fictional.</footer>
</body></html>`;
}

export function createApp({ secret }) {
  if (!secret) throw new Error("WAF_SHARED_SECRET is required: refusing to start without bypass protection.");

  const app = express();
  app.disable("x-powered-by");
  app.use(requireWaf(secret));
  app.use(express.static(path.join(here, "..", "public")));
  app.use(express.urlencoded({ extended: false, limit: "100kb" }));
  app.use(express.json({ limit: "100kb" }));

  app.get("/", (_req, res) => {
    res.send(
      page(
        "Home",
        `<h1>Welcome to SecureShop</h1><p>This small shop exists so the WAF has a real website to protect.</p>
<form action="/products" method="get"><label for="q">Search products</label>
<input id="q" name="q" placeholder="Try: book"><button>Search</button></form>`,
      ),
    );
  });

  app.get("/products", (req, res) => {
    const q = String(req.query.q ?? "").toLowerCase();
    const results = PRODUCTS.filter((p) => p.name.toLowerCase().includes(q) || p.category.includes(q));
    const rows = results
      .map((p) => `<li><a href="/products/${p.id}">${escapeHtml(p.name)}</a> <span>$${p.price}</span></li>`)
      .join("");
    res.send(
      page(
        "Products",
        `<h1>Products</h1>${q ? `<p>Results for: <b>${escapeHtml(q)}</b></p>` : ""}<ul class="list">${rows || "<li>No products found.</li>"}</ul>`,
      ),
    );
  });

  app.get("/products/:id", (req, res) => {
    const product = PRODUCTS.find((p) => p.id === Number(req.params.id));
    if (!product) return res.status(404).send(page("Not found", "<h1>Product not found</h1>"));
    res.send(page(product.name, `<h1>${escapeHtml(product.name)}</h1><p>Category: ${escapeHtml(product.category)}</p><p>Price: $${product.price}</p>`));
  });

  app.get("/contact", (_req, res) => {
    res.send(
      page(
        "Contact",
        `<h1>Contact us</h1><form method="post" action="/contact">
<label for="name">Name</label><input id="name" name="name" required>
<label for="message">Message</label><textarea id="message" name="message" required></textarea>
<button>Send</button></form>`,
      ),
    );
  });

  app.post("/contact", (req, res) => {
    const name = String(req.body?.name ?? "");
    res.send(page("Thanks", `<h1>Thanks, ${escapeHtml(name)}</h1><p>Your message was received. Nothing is stored.</p>`));
  });

  app.get("/api/products", (req, res) => {
    const category = req.query.category;
    res.json({ items: category ? PRODUCTS.filter((p) => p.category === category) : PRODUCTS });
  });

  app.get("/api/products/:id", (req, res) => {
    const product = PRODUCTS.find((p) => p.id === Number(req.params.id));
    if (!product) return res.status(404).json({ error: "not_found" });
    res.json(product);
  });

  app.post("/api/orders", (req, res) => {
    const productId = Number(req.body?.productId);
    const quantity = Number(req.body?.quantity ?? 1);
    if (!PRODUCTS.some((p) => p.id === productId) || !Number.isInteger(quantity) || quantity < 1) {
      return res.status(400).json({ error: "invalid_order" });
    }
    res.status(201).json({ ok: true, productId, quantity, note: "Demo order, nothing is stored." });
  });

  app.get("/redirect-home", (_req, res) => res.redirect("/"));
  app.get("/healthz", (_req, res) => res.json({ status: "ok" }));

  app.use((_req, res) => res.status(404).send(page("Not found", "<h1>Page not found</h1>")));
  return app;
}
