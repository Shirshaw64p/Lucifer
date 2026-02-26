"""
Tests for tools/specialized/web_crawler.py — WebCrawler.

All HTTP requests are mocked via httpx MockTransport.
"""
from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from core.scope_guard import ScopeViolation, reset_scope_guard
from tools.specialized.web_crawler import WebCrawler, CrawlResult


@pytest.fixture(autouse=True)
def _scope(tmp_path: Path):
    sf = tmp_path / "scope.yaml"
    sf.write_text("scope:\n  includes:\n    - '*.example.com'\n    - 'example.com'\n")
    reset_scope_guard(str(sf))
    yield
    reset_scope_guard(str(sf))


MOCK_HTML = """
<html>
<head><title>Test Page</title></head>
<body>
  <a href="/about">About</a>
  <a href="https://app.example.com/contact">Contact</a>
  <a href="https://evil.com/steal">Evil</a>
  <form action="/login" method="POST">
    <input type="text" name="username" />
    <input type="password" name="password" />
    <input type="hidden" name="csrf" value="tok123" />
  </form>
  <script>
    fetch('/api/v1/users');
    axios.get('/api/v1/settings');
  </script>
</body>
</html>
"""


class TestWebCrawlerForms:
    @pytest.mark.asyncio
    async def test_discover_forms(self) -> None:
        crawler = WebCrawler()

        async def handler(req: httpx.Request) -> httpx.Response:
            return httpx.Response(200, text=MOCK_HTML, headers={"content-type": "text/html"})

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            resp = await client.get("https://app.example.com/page")
            forms = crawler._extract_forms(resp.text, "https://app.example.com/page")

        assert len(forms) == 1
        assert forms[0].method == "POST"
        assert any(f.name == "username" for f in forms[0].fields)
        assert any(f.name == "csrf" for f in forms[0].fields)

    @pytest.mark.asyncio
    async def test_discover_forms_scope_violation(self) -> None:
        crawler = WebCrawler()
        with pytest.raises(ScopeViolation):
            await crawler.discover_forms("https://evil.com/page")


class TestWebCrawlerLinks:
    def test_extract_links_filters_scope(self) -> None:
        crawler = WebCrawler()
        links = crawler._extract_links(MOCK_HTML, "https://app.example.com/page")

        # Evil link should be filtered out by scope
        assert not any("evil.com" in l for l in links)
        # In-scope links should be present
        assert any("about" in l for l in links)
        assert any("contact" in l for l in links)


class TestWebCrawlerJS:
    def test_extract_js_endpoints(self) -> None:
        endpoints = WebCrawler._extract_js_endpoints(MOCK_HTML)

        assert "/api/v1/users" in endpoints
        assert "/api/v1/settings" in endpoints

    @pytest.mark.asyncio
    async def test_extract_js_endpoints_scope_violation(self) -> None:
        crawler = WebCrawler()
        with pytest.raises(ScopeViolation):
            await crawler.extract_js_endpoints("https://evil.com/page")
