"""
tools/browser_engine.py — BrowserEngine: Playwright-based async browser automation
with scope enforcement, DOM snapshots, and evidence capture.

One isolated browser context per agent instance.
All navigation validated through scope_guard.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from core.models import ArtifactType, EvidenceRef, PageSnapshot
from core.scope_guard import check_scope, ScopeViolation
from tools.evidence_store import EvidenceStore

logger = logging.getLogger(__name__)


class BrowserEngine:
    """
    Playwright async — one isolated browser context per agent.

    * ``navigate(url)`` → ``PageSnapshot``
    * ``interact(actions)`` → ``PageSnapshot``
    * ``screenshot(url)`` → ``EvidenceRef``
    * Scope enforcement on every navigation
    """

    def __init__(
        self,
        evidence_store: Optional[EvidenceStore] = None,
        headless: bool = True,
        timeout_ms: float = 30_000,
    ) -> None:
        self._store = evidence_store or EvidenceStore()
        self._headless = headless
        self._timeout_ms = timeout_ms
        self._playwright: Any = None
        self._browser: Any = None
        self._context: Any = None
        self._page: Any = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def launch(self) -> None:
        """Start Playwright and create an isolated browser context."""
        from playwright.async_api import async_playwright  # type: ignore[import-untyped]

        self._playwright = await async_playwright().start()
        self._browser = await self._playwright.chromium.launch(headless=self._headless)
        self._context = await self._browser.new_context(
            ignore_https_errors=True,
            java_script_enabled=True,
        )
        self._context.set_default_timeout(self._timeout_ms)
        self._page = await self._context.new_page()

    async def close(self) -> None:
        """Tear down browser resources."""
        if self._context:
            await self._context.close()
        if self._browser:
            await self._browser.close()
        if self._playwright:
            await self._playwright.stop()
        self._page = self._context = self._browser = self._playwright = None

    async def _ensure_page(self) -> Any:
        if self._page is None:
            await self.launch()
        return self._page

    # ------------------------------------------------------------------
    # Navigation
    # ------------------------------------------------------------------

    async def navigate(self, url: str) -> PageSnapshot:
        """
        Navigate to *url* and return a ``PageSnapshot``.

        Raises ``ScopeViolation`` if the URL is out of scope.
        """
        check_scope(url)

        page = await self._ensure_page()
        response = await page.goto(url, wait_until="domcontentloaded")

        status = response.status if response else 0
        title = await page.title()
        dom = await page.content()

        cookies_raw = await self._context.cookies()
        cookies = [
            {"name": c["name"], "value": c["value"], "domain": c.get("domain", "")}
            for c in cookies_raw
        ]

        return PageSnapshot(
            url=page.url,
            title=title,
            status=status,
            dom_html=dom,
            cookies=cookies,
        )

    # ------------------------------------------------------------------
    # Interactions
    # ------------------------------------------------------------------

    async def interact(self, actions: List[Dict[str, Any]]) -> PageSnapshot:
        """
        Execute a sequence of browser actions and return the resulting snapshot.

        Supported action types:
            ``click``  — ``{"type": "click", "selector": "#btn"}``
            ``fill``   — ``{"type": "fill", "selector": "#email", "value": "x"}``
            ``submit`` — ``{"type": "submit", "selector": "form"}``
            ``wait``   — ``{"type": "wait", "ms": 1000}``
        """
        page = await self._ensure_page()

        for action in actions:
            atype = action.get("type", "")
            selector = action.get("selector", "")

            if atype == "click":
                await page.click(selector)
            elif atype == "fill":
                await page.fill(selector, action.get("value", ""))
            elif atype == "submit":
                await page.locator(selector).evaluate("el => el.submit()")
            elif atype == "wait":
                await page.wait_for_timeout(action.get("ms", 1000))
            else:
                logger.warning("browser_engine.unknown_action", extra={"action": atype})

        # Validate current page URL is still in scope
        try:
            check_scope(page.url)
        except ScopeViolation:
            logger.error("browser_engine.scope_violation_after_interact", extra={"url": page.url})
            raise

        title = await page.title()
        dom = await page.content()
        cookies_raw = await self._context.cookies()
        cookies = [
            {"name": c["name"], "value": c["value"], "domain": c.get("domain", "")}
            for c in cookies_raw
        ]

        status = 200  # Post-interaction; no direct HTTP response code available
        return PageSnapshot(
            url=page.url, title=title, status=status, dom_html=dom, cookies=cookies
        )

    # ------------------------------------------------------------------
    # Screenshot
    # ------------------------------------------------------------------

    async def screenshot(
        self,
        url: str,
        *,
        full_page: bool = True,
        run_id: Optional[str] = None,
        finding_id: Optional[str] = None,
    ) -> EvidenceRef:
        """
        Navigate to *url*, capture a PNG screenshot, and store it.

        Returns an ``EvidenceRef`` pointing to the stored PNG.
        """
        check_scope(url)

        page = await self._ensure_page()
        await page.goto(url, wait_until="domcontentloaded")

        png_bytes: bytes = await page.screenshot(full_page=full_page, type="png")

        metadata: Dict[str, Any] = {"url": url}
        if run_id:
            metadata["run_id"] = run_id
        if finding_id:
            metadata["finding_id"] = finding_id

        return self._store.save(ArtifactType.SCREENSHOT, png_bytes, metadata)
