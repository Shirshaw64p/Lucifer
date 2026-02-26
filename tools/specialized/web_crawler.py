"""
tools/specialized/web_crawler.py — Scrapy-based endpoint and form discovery.

Discovers URLs, forms, parameters, JavaScript endpoints, and API routes.
"""
from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse

import httpx

from core.scope_guard import check_scope, ScopeViolation

logger = logging.getLogger(__name__)


@dataclass
class FormField:
    name: str
    input_type: str      # text, password, hidden, …
    value: str = ""


@dataclass
class DiscoveredForm:
    action: str
    method: str
    fields: List[FormField] = field(default_factory=list)
    page_url: str = ""


@dataclass
class CrawlResult:
    start_url: str
    urls_discovered: List[str] = field(default_factory=list)
    forms: List[DiscoveredForm] = field(default_factory=list)
    js_endpoints: List[str] = field(default_factory=list)
    parameters: List[Dict[str, str]] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


class WebCrawler:
    """
    Async web crawler for endpoint and form discovery.

    Falls back to a lightweight httpx + regex crawler when Scrapy is
    unavailable (CI / test environments).

    * ``crawl()``           — full site crawl
    * ``discover_forms()``  — extract HTML forms from a page
    * ``extract_js_endpoints()`` — parse JS for API routes
    """

    def __init__(
        self,
        max_depth: int = 3,
        max_pages: int = 200,
        timeout: float = 15.0,
        concurrency: int = 10,
    ) -> None:
        self._max_depth = max_depth
        self._max_pages = max_pages
        self._timeout = timeout
        self._concurrency = concurrency

    # ------------------------------------------------------------------
    # Main crawl
    # ------------------------------------------------------------------

    async def crawl(self, start_url: str) -> CrawlResult:
        """Breadth-first crawl from *start_url*."""
        check_scope(start_url)

        result = CrawlResult(start_url=start_url)
        visited: Set[str] = set()
        queue: List[tuple[str, int]] = [(start_url, 0)]
        sem = asyncio.Semaphore(self._concurrency)

        async with httpx.AsyncClient(
            timeout=self._timeout,
            follow_redirects=True,
            verify=False,
        ) as client:
            while queue and len(visited) < self._max_pages:
                batch = []
                while queue and len(batch) < self._concurrency:
                    url, depth = queue.pop(0)
                    if url in visited or depth > self._max_depth:
                        continue
                    try:
                        check_scope(url)
                    except ScopeViolation:
                        continue
                    visited.add(url)
                    batch.append((url, depth))

                tasks = [
                    self._fetch_and_parse(client, sem, url, depth, result)
                    for url, depth in batch
                ]
                link_batches = await asyncio.gather(*tasks, return_exceptions=True)

                for links in link_batches:
                    if isinstance(links, list):
                        for link in links:
                            if link not in visited:
                                queue.append((link, depth + 1))

        result.urls_discovered = sorted(visited)
        return result

    async def _fetch_and_parse(
        self,
        client: httpx.AsyncClient,
        sem: asyncio.Semaphore,
        url: str,
        depth: int,
        result: CrawlResult,
    ) -> List[str]:
        """Fetch URL, extract links/forms/JS endpoints."""
        links: List[str] = []
        async with sem:
            try:
                resp = await client.get(url)
                html = resp.text
                content_type = resp.headers.get("content-type", "")

                if "text/html" not in content_type:
                    return links

                # Extract links
                links = self._extract_links(html, str(resp.url))

                # Extract forms
                forms = self._extract_forms(html, str(resp.url))
                result.forms.extend(forms)

                # Extract JS endpoints
                js_eps = self._extract_js_endpoints(html)
                result.js_endpoints.extend(js_eps)

                # Extract query parameters
                for link in links:
                    parsed = urlparse(link)
                    if parsed.query:
                        for param in parsed.query.split("&"):
                            if "=" in param:
                                name, val = param.split("=", 1)
                                result.parameters.append(
                                    {"url": link, "name": name, "value": val}
                                )

            except Exception as exc:
                result.errors.append(f"{url}: {exc}")

        return links

    # ------------------------------------------------------------------
    # HTML parsing helpers
    # ------------------------------------------------------------------

    def _extract_links(self, html: str, base_url: str) -> List[str]:
        """Extract href and src links from HTML."""
        links: List[str] = []
        patterns = [
            r'href=["\']([^"\']+)["\']',
            r'src=["\']([^"\']+)["\']',
            r'action=["\']([^"\']+)["\']',
        ]
        for pat in patterns:
            for match in re.finditer(pat, html, re.IGNORECASE):
                raw = match.group(1).strip()
                if raw.startswith(("javascript:", "mailto:", "data:", "#")):
                    continue
                full = urljoin(base_url, raw)
                try:
                    check_scope(full)
                    links.append(full)
                except ScopeViolation:
                    pass
        return list(set(links))

    def _extract_forms(self, html: str, page_url: str) -> List[DiscoveredForm]:
        """Extract HTML forms and their input fields."""
        forms: List[DiscoveredForm] = []
        form_pattern = re.compile(
            r"<form[^>]*>(.*?)</form>", re.IGNORECASE | re.DOTALL
        )
        for form_match in form_pattern.finditer(html):
            form_html = form_match.group(0)
            action_m = re.search(r'action=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
            method_m = re.search(r'method=["\']([^"\']*)["\']', form_html, re.IGNORECASE)

            action = urljoin(page_url, action_m.group(1)) if action_m else page_url
            method = (method_m.group(1).upper() if method_m else "GET")

            fields: List[FormField] = []
            input_pattern = re.compile(
                r"<input[^>]*>", re.IGNORECASE
            )
            for inp in input_pattern.finditer(form_html):
                tag = inp.group(0)
                name_m = re.search(r'name=["\']([^"\']*)["\']', tag, re.IGNORECASE)
                type_m = re.search(r'type=["\']([^"\']*)["\']', tag, re.IGNORECASE)
                value_m = re.search(r'value=["\']([^"\']*)["\']', tag, re.IGNORECASE)
                if name_m:
                    fields.append(
                        FormField(
                            name=name_m.group(1),
                            input_type=(type_m.group(1) if type_m else "text"),
                            value=(value_m.group(1) if value_m else ""),
                        )
                    )

            # Also capture textareas and selects
            for ta in re.finditer(r'<textarea[^>]*name=["\']([^"\']*)["\']', form_html, re.I):
                fields.append(FormField(name=ta.group(1), input_type="textarea"))

            forms.append(
                DiscoveredForm(
                    action=action, method=method, fields=fields, page_url=page_url
                )
            )

        return forms

    @staticmethod
    def _extract_js_endpoints(html: str) -> List[str]:
        """Extract API-like endpoints from inline/embedded JavaScript."""
        endpoints: List[str] = []
        # Common API route patterns
        patterns = [
            r'["\'](/api/[^"\']+)["\']',
            r'["\'](/v[0-9]+/[^"\']+)["\']',
            r'fetch\(["\']([^"\']+)["\']',
            r'axios\.[a-z]+\(["\']([^"\']+)["\']',
            r'\.ajax\(\{[^}]*url:\s*["\']([^"\']+)["\']',
            r'XMLHttpRequest[^;]*open\([^,]*,\s*["\']([^"\']+)["\']',
        ]
        for pat in patterns:
            for match in re.finditer(pat, html, re.IGNORECASE):
                ep = match.group(1).strip()
                if ep and not ep.startswith(("data:", "javascript:")):
                    endpoints.append(ep)
        return list(set(endpoints))

    # ------------------------------------------------------------------
    # Single-page utilities
    # ------------------------------------------------------------------

    async def discover_forms(self, url: str) -> List[DiscoveredForm]:
        """Fetch *url* and return all discovered forms."""
        check_scope(url)
        async with httpx.AsyncClient(timeout=self._timeout, follow_redirects=True, verify=False) as c:
            resp = await c.get(url)
            return self._extract_forms(resp.text, str(resp.url))

    async def extract_js_endpoints(self, url: str) -> List[str]:
        """Fetch *url* and return JS-embedded API endpoints."""
        check_scope(url)
        async with httpx.AsyncClient(timeout=self._timeout, follow_redirects=True, verify=False) as c:
            resp = await c.get(url)
            return self._extract_js_endpoints(resp.text)
