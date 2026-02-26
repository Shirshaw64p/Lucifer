"""
Tests for tools/browser_engine.py — BrowserEngine.

All Playwright calls are mocked — no real browser is launched.
"""
from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from core.models import ArtifactType, PageSnapshot
from core.scope_guard import ScopeViolation, reset_scope_guard
from tools.evidence_store import EvidenceStore
from tools.browser_engine import BrowserEngine


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def tmp_evidence(tmp_path: Path) -> EvidenceStore:
    return EvidenceStore(backend="filesystem", root=str(tmp_path / "ev"))


@pytest.fixture(autouse=True)
def _scope(tmp_path: Path):
    scope_file = tmp_path / "scope.yaml"
    scope_file.write_text(
        "scope:\n  includes:\n    - '*.example.com'\n    - 'example.com'\n"
    )
    reset_scope_guard(str(scope_file))
    yield
    reset_scope_guard(str(scope_file))


def _mock_page(url: str = "https://app.example.com", title: str = "Test", status: int = 200):
    """Create a mocked Playwright page object."""
    page = AsyncMock()
    page.url = url
    page.title = AsyncMock(return_value=title)
    page.content = AsyncMock(return_value="<html><body>Hi</body></html>")
    page.screenshot = AsyncMock(return_value=b"\x89PNG_fake_screenshot_bytes")
    page.goto = AsyncMock(return_value=MagicMock(status=status))
    page.click = AsyncMock()
    page.fill = AsyncMock()
    page.wait_for_timeout = AsyncMock()
    page.locator = MagicMock(return_value=MagicMock(evaluate=AsyncMock()))
    return page


def _mock_context(page):
    ctx = AsyncMock()
    ctx.new_page = AsyncMock(return_value=page)
    ctx.cookies = AsyncMock(return_value=[{"name": "sid", "value": "abc", "domain": ".example.com"}])
    ctx.close = AsyncMock()
    ctx.set_default_timeout = MagicMock()
    return ctx


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestBrowserNavigate:
    @pytest.mark.asyncio
    async def test_navigate_returns_page_snapshot(self, tmp_evidence: EvidenceStore) -> None:
        engine = BrowserEngine(evidence_store=tmp_evidence)

        page = _mock_page()
        ctx = _mock_context(page)
        engine._page = page
        engine._context = ctx

        snap = await engine.navigate("https://app.example.com/login")

        assert isinstance(snap, PageSnapshot)
        assert snap.title == "Test"
        assert snap.dom_html == "<html><body>Hi</body></html>"
        assert snap.status == 200

    @pytest.mark.asyncio
    async def test_navigate_scope_violation(self, tmp_evidence: EvidenceStore) -> None:
        engine = BrowserEngine(evidence_store=tmp_evidence)

        with pytest.raises(ScopeViolation):
            await engine.navigate("https://evil.site.com/steal")

    @pytest.mark.asyncio
    async def test_screenshot_stores_evidence(self, tmp_evidence: EvidenceStore) -> None:
        engine = BrowserEngine(evidence_store=tmp_evidence)

        page = _mock_page()
        ctx = _mock_context(page)
        engine._page = page
        engine._context = ctx

        ref = await engine.screenshot("https://app.example.com/dashboard")

        assert ref.artifact_type == ArtifactType.SCREENSHOT
        artifact = tmp_evidence.get(sha256=ref.sha256)
        assert artifact.content == b"\x89PNG_fake_screenshot_bytes"


class TestBrowserInteract:
    @pytest.mark.asyncio
    async def test_interact_executes_actions(self, tmp_evidence: EvidenceStore) -> None:
        engine = BrowserEngine(evidence_store=tmp_evidence)

        page = _mock_page()
        ctx = _mock_context(page)
        engine._page = page
        engine._context = ctx

        actions = [
            {"type": "fill", "selector": "#user", "value": "admin"},
            {"type": "click", "selector": "#submit"},
        ]
        snap = await engine.interact(actions)

        page.fill.assert_awaited_once_with("#user", "admin")
        page.click.assert_awaited_once_with("#submit")
        assert isinstance(snap, PageSnapshot)
