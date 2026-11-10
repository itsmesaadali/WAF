"""Simulated NORMAL website traffic, used to teach the model what ordinary looks like.

This is simulated data, and the report must say so. After real traffic has passed through
the WAF, training with --source observed adds it to improve accuracy for that site.
Every generator is seeded, so a dataset can be reproduced exactly.
"""
from __future__ import annotations

import random
import string
from urllib.parse import urlencode

from .features import RequestView

BROWSER_AGENTS = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Mobile/15E148 Safari/604.1",
)
SCRIPT_AGENTS = ("python-httpx/0.28.1", "curl/8.9.1", "PostmanRuntime/7.42.0", "node", "okhttp/4.12.0")
PAGES = ("/", "/products", "/contact", "/about", "/blog", "/projects", "/resume", "/pricing", "/faq", "/login", "/cart")
WORDS = (
    "book", "device", "security", "laptop", "training", "network", "key", "guide", "handbook", "lab",
    "cards", "primer", "pakistan", "islamabad", "student", "project", "resume", "portfolio", "contact", "shoes",
    "phone", "price", "best", "cheap", "new", "review", "design", "developer", "course", "university",
)
NAMES = ("Saad", "Abrar", "Sara", "Ali", "Fatima", "Bilal", "O'Brien", "Maria", "Chen", "Ayesha")
SENTENCES = (
    "Please send more details about this product.",
    "It's a great site, thanks for your help!",
    "When will my order arrive?",
    "Do you ship to Islamabad?",
    "I'd like to discuss a project with you.",
    "Is this available in another colour?",
)


def _hash(rng: random.Random, length: int) -> str:
    return "".join(rng.choices(string.hexdigits.lower()[:16], k=length))


def _page(rng: random.Random) -> tuple[str, str, str, bytes, dict]:
    path = rng.choice(PAGES)
    if rng.random() < 0.15:
        path = f"{path.rstrip('/')}/{rng.choice(WORDS)}-{rng.choice(WORDS)}"
    return "GET", path, "", b"", {}


def _search(rng: random.Random) -> tuple[str, str, str, bytes, dict]:
    terms = " ".join(rng.choices(WORDS, k=rng.randint(1, 4)))
    params = {"q": terms}
    if rng.random() < 0.3:
        params["page"] = str(rng.randint(1, 20))
    if rng.random() < 0.2:
        params["sort"] = rng.choice(("price", "newest", "rating"))
    return "GET", rng.choice(("/products", "/search", "/blog")), urlencode(params), b"", {}


def _asset(rng: random.Random) -> tuple[str, str, str, bytes, dict]:
    kind = rng.random()
    if kind < 0.5:
        path = f"/_next/static/chunks/{rng.randint(100, 9999)}-{_hash(rng, 16)}.js"
    elif kind < 0.7:
        path = f"/_next/static/css/{_hash(rng, 16)}.css"
    elif kind < 0.85:
        path = f"/_next/static/media/{_hash(rng, 8)}.woff2"
    else:
        path = rng.choice(("/styles.css", "/favicon.ico", "/robots.txt", "/images/hero.webp", "/logo.svg"))
    query = ""
    if rng.random() < 0.1:
        query = urlencode({"url": f"/images/{rng.choice(WORDS)}.jpg", "w": rng.choice((640, 750, 1080)), "q": 75})
        path = "/_next/image"
    return "GET", path, query, b"", {"asset": True}


def _api_read(rng: random.Random) -> tuple[str, str, str, bytes, dict]:
    if rng.random() < 0.5:
        return "GET", f"/api/products/{rng.randint(1, 500)}", "", b"", {"api": True}
    query = urlencode({"category": rng.choice(WORDS), "limit": rng.choice((10, 20, 50)), "offset": rng.randrange(0, 500, 10)})
    return "GET", "/api/products", query, b"", {"api": True}


def _form(rng: random.Random) -> tuple[str, str, str, bytes, dict]:
    body = urlencode({"name": rng.choice(NAMES), "message": rng.choice(SENTENCES)}).encode()
    return "POST", "/contact", "", body, {}


def _api_write(rng: random.Random) -> tuple[str, str, str, bytes, dict]:
    body = f'{{"productId": {rng.randint(1, 500)}, "quantity": {rng.randint(1, 9)}}}'.encode()
    method = rng.choices(("POST", "PUT", "PATCH", "DELETE"), weights=(8, 1, 1, 1))[0]
    path = "/api/orders" if method == "POST" else f"/api/orders/{rng.randint(1, 5000)}"
    return method, path, "", b"" if method == "DELETE" else body, {"api": True}


_SHAPES = ((_page, 30), (_search, 15), (_asset, 35), (_api_read, 12), (_form, 4), (_api_write, 4))


def generate_normal(count: int, seed: int) -> list[RequestView]:
    """Return simulated normal requests from browsers and scripted API clients."""
    rng = random.Random(seed)
    makers = [m for m, _ in _SHAPES]
    weights = [w for _, w in _SHAPES]
    views: list[RequestView] = []
    for _ in range(count):
        method, path, query, body, meta = rng.choices(makers, weights=weights)[0](rng)
        is_script = bool(meta.get("api")) and rng.random() < 0.6 or rng.random() < 0.05
        agent = rng.choice(SCRIPT_AGENTS) if is_script else rng.choice(BROWSER_AGENTS)
        # Behaviour: page visits are slow, loading assets or polling an API is faster.
        rate = max(1, int(rng.lognormvariate(3.1 if meta.get("asset") else 2.2, 0.8)))
        rate = min(rate, 110)
        views.append(
            RequestView(
                method=method,
                path=path,
                query=query,
                header_count=rng.randint(3, 8) if is_script else rng.randint(8, 18),
                user_agent=agent,
                has_accept=True if not is_script else rng.random() < 0.9,
                body=body,
                requests_last_minute=rate,
                unique_paths_last_minute=max(1, int(rate * rng.uniform(0.2, 0.9))),
                error_ratio_last_minute=rng.choice((0.0, 0.0, 0.0, 0.0, 0.02, 0.05, 0.1)),
            )
        )
    return views
