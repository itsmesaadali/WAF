"""SQL injection and XSS signatures.

The approach follows the ideas of the OWASP Core Rule Set: normalize first, then match
behaviours instead of exact strings. Rule patterns here are written for this project.

Patterns avoid nested repetition and use bounded gaps, so they cannot backtrack for a
long time. tests/unit/test_signatures.py includes a worst-case timing test.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal

Attack = Literal["sqli", "xss"]
Severity = Literal["medium", "high", "critical"]


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    attack: Attack
    severity: Severity
    pattern: re.Pattern[str]
    # "normal" matches normalized text; "compact" matches text with all spaces removed.
    form: Literal["normal", "compact"] = "normal"


def _rule(id_: str, name: str, attack: Attack, severity: Severity, pattern: str, form: str = "normal") -> Rule:
    return Rule(id_, name, attack, severity, re.compile(pattern), form)  # type: ignore[arg-type]


SQLI_RULES: tuple[Rule, ...] = (
    _rule("SQLI-001", "UNION SELECT data extraction", "sqli", "critical",
          r"\bunion\b(?:\s+all|\s+distinct)?\s*\(?\s*select\b"),
    _rule("SQLI-002", "UNION SELECT hidden with comments or spacing", "sqli", "critical",
          r"union(?:all|distinct)?\(?select(?:\d|null|@@|\*|[a-z_(]|'|\")", "compact"),
    _rule("SQLI-003", "Boolean tautology after a quote", "sqli", "critical",
          r"['\"`)]\s*(?:or|and|\|\||&&)\s*\(?\s*['\"]?[\w-]{0,32}['\"]?\s*(?:=|<=>|<>|!=|<|>|\blike\b|\bis\b)"),
    _rule("SQLI-004", "Numeric tautology such as OR 1=1", "sqli", "high",
          r"(?:^|[\s(])(?:or|and)\s+\(?(\d{1,9})\)?\s*=\s*\(?\1\)?(?:\s|$|--|#|;|\))"),
    _rule("SQLI-005", "Quote followed by a comment terminator", "sqli", "high",
          r"['\"`]\s*\)?\s*;?\s*(?:--(?:\s|$)|#|/\*)"),
    _rule("SQLI-006", "Stacked destructive query", "sqli", "critical",
          r";\s*(?:drop|delete|truncate|alter|update|insert|create|exec|execute|grant|shutdown|merge)\b"),
    _rule("SQLI-007", "Destructive statement", "sqli", "critical",
          r"\b(?:drop\s+(?:table|database|schema)|truncate\s+table|delete\s+from\s+\w+\s*(?:where\b|;|--)|insert\s+into\s+\w+\s*(?:\(|values\b|select\b)|update\s+\w+\s+set\s+\w+\s*=)"),
    _rule("SQLI-008", "Time-based blind injection", "sqli", "critical",
          r"\b(?:sleep\s*\(\s*\d|pg_sleep\s*\(|benchmark\s*\(\s*\d|waitfor\s+delay\b|dbms_pipe\.receive_message|dbms_lock\.sleep)"),
    _rule("SQLI-009", "Database metadata access", "sqli", "high",
          r"\b(?:information_schema\.\w|pg_catalog\.\w|sysobjects\b|syscolumns\b|sqlite_master\b|mysql\.user\b|pg_shadow\b|sys\.databases\b)"),
    _rule("SQLI-010", "File or command access through the database", "sqli", "critical",
          r"\b(?:load_file\s*\(|into\s+(?:out|dump)file\b|xp_cmdshell\b|sp_oacreate\b|copy\s+\w+\s+(?:from|to)\s+program\b)"),
    _rule("SQLI-011", "Error-based extraction function", "sqli", "high",
          r"\b(?:extractvalue|updatexml|exp\s*\(\s*~|polygon|gtid_subset|json_keys)\s*\("),
    _rule("SQLI-012", "Query fingerprinting or casting", "sqli", "medium",
          r"(?:@@version\b|\bversion\s*\(\s*\)|\bcurrent_user\s*\(\s*\)|\bdatabase\s*\(\s*\)|\bconvert\s*\(\s*int\b|\bcast\s*\(\s*\(?\s*select\b)"),
    _rule("SQLI-013", "Sub-select after a quote or operator", "sqli", "high",
          r"['\"=(]\s*\(?\s*select\b.{0,120}\bfrom\b"),
    _rule("SQLI-014", "ORDER BY or GROUP BY column probing", "sqli", "high",
          r"['\"`)\d]\s*(?:order|group)\s+by\s+\d{1,4}\s*(?:--|#|$|,|\))"),
    _rule("SQLI-015", "Character building to hide strings", "sqli", "medium",
          r"\b(?:concat(?:_ws)?\s*\(.{0,80}(?:select|0x[0-9a-f]{2}|char\s*\()|char\s*\(\s*\d{1,3}\s*(?:,\s*\d{1,3}\s*){2,}\)|0x[0-9a-f]{16,})"),
)

XSS_RULES: tuple[Rule, ...] = (
    _rule("XSS-001", "Script tag", "xss", "critical", r"<\s*/?\s*script\b"),
    _rule("XSS-002", "Script tag hidden with spacing", "xss", "critical", r"<script[\s/>]|</script", "compact"),
    _rule("XSS-003", "Inline event handler in markup", "xss", "high",
          r"<[a-z!/][^>]{0,400}[\s/\"'`]on[a-z]{3,24}\s*="),
    _rule("XSS-004", "Event handler breaking out of an attribute", "xss", "high",
          r"['\"`]\s*[\s/]*on[a-z]{3,24}\s*=\s*"),
    _rule("XSS-005", "Script URL", "xss", "high",
          r"(?:java|vb|live)script:|data:\w{0,16}/?[\w+.-]{0,32}[^,]{0,32};base64|data:text/html", "compact"),
    _rule("XSS-006", "Dangerous embedding tag", "xss", "high",
          r"<\s*(?:iframe|object|embed|applet|meta|base|link|svg|math|marquee|isindex|frameset|template|video|audio|details|body|img|input|form|style)\b[^>]{0,400}(?:\bon[a-z]{3,24}\s*=|\b(?:src|href|data|action|formaction|srcdoc|code|content|background|xlink:href)\s*=\s*['\"`]?\s*(?:javascript|data|vbscript)|\bsrcdoc\s*=)"),
    _rule("XSS-007", "Frame or object tag", "xss", "medium", r"<\s*(?:iframe|object|embed|applet|frameset)\b"),
    _rule("XSS-008", "SVG with animation or script behaviour", "xss", "high",
          r"<\s*svg\b.{0,300}?<\s*(?:animate|set|script|foreignobject)\b"),
    _rule("XSS-009", "Script code that reads or runs sensitive objects", "xss", "high",
          r"\b(?:document\s*\.\s*(?:cookie|domain|write(?:ln)?\s*\(|location\s*=)|window\s*\.\s*location\s*=|localstorage\s*\.\s*getitem\s*\(|eval\s*\(\s*(?:atob|string\.|['\"`]|unescape)|new\s+function\s*\(|fromcharcode\s*\()"),
    _rule("XSS-010", "Common test call inside markup or quotes", "xss", "medium",
          r"(?:^|[<>\"'`;(=])\s*(?:alert|confirm|prompt)\s*(?:\(|`)\s*(?:['\"`]?\s*(?:\d{1,6}|document\b|xss\b|origin\b|1\b)|\s*\))"),
    _rule("XSS-011", "CSS expression or import abuse", "xss", "medium",
          r"(?:expression\s*\(|@import\s+['\"]?\s*(?:javascript|https?:)|behavior\s*:\s*url\s*\(|-moz-binding\s*:)"),
)

ALL_RULES: tuple[Rule, ...] = SQLI_RULES + XSS_RULES
