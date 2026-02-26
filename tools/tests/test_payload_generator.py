"""
Tests for tools/specialized/payload_generator.py — PayloadGenerator.

Pure-logic tests — no external services.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from tools.specialized.payload_generator import (
    Payload,
    PayloadCategory,
    PayloadGenerator,
)


@pytest.fixture
def gen() -> PayloadGenerator:
    return PayloadGenerator()


class TestPayloadRetrieval:
    def test_get_sqli_payloads(self, gen: PayloadGenerator) -> None:
        payloads = gen.get(PayloadCategory.SQLI)
        assert len(payloads) >= 10
        assert all(isinstance(p, Payload) for p in payloads)
        assert all(p.category == PayloadCategory.SQLI for p in payloads)

    def test_get_xss_payloads(self, gen: PayloadGenerator) -> None:
        payloads = gen.get(PayloadCategory.XSS)
        assert len(payloads) >= 10
        assert any("<script>" in p.value for p in payloads)

    def test_get_with_limit(self, gen: PayloadGenerator) -> None:
        payloads = gen.get(PayloadCategory.CMDI, limit=3)
        assert len(payloads) == 3

    def test_get_all_categories(self, gen: PayloadGenerator) -> None:
        all_payloads = gen.get_all(limit_per_category=2)
        categories_seen = {p.category for p in all_payloads}
        assert PayloadCategory.SQLI in categories_seen
        assert PayloadCategory.XSS in categories_seen
        assert PayloadCategory.SSTI in categories_seen


class TestPayloadMutation:
    def test_mutate_url_encoding(self, gen: PayloadGenerator) -> None:
        original = Payload(value="<script>alert(1)</script>", category=PayloadCategory.XSS)
        variants = gen.mutate(original, encodings=["url"])
        assert len(variants) >= 1
        assert "%3C" in variants[0].value or "%3c" in variants[0].value

    def test_mutate_base64_encoding(self, gen: PayloadGenerator) -> None:
        original = Payload(value="' OR '1'='1", category=PayloadCategory.SQLI)
        variants = gen.mutate(original, encodings=["base64"])
        assert len(variants) >= 1
        # Base64 should not contain the raw quotes
        assert "'" not in variants[0].value

    def test_mutate_multiple_encodings(self, gen: PayloadGenerator) -> None:
        original = Payload(value="{{7*7}}", category=PayloadCategory.SSTI)
        variants = gen.mutate(original)
        assert len(variants) >= 3  # url, double_url, html, base64


class TestPayloadOAST:
    def test_with_oast_replaces_placeholder(self, gen: PayloadGenerator) -> None:
        payloads = gen.get(PayloadCategory.CMDI)
        oast_url = "http://abc123.interact.sh"
        augmented = gen.with_oast(payloads, oast_url)

        has_oast = any(oast_url in p.value for p in augmented)
        assert has_oast


class TestPayloadCustomWordlist:
    def test_load_custom(self, gen: PayloadGenerator, tmp_path: Path) -> None:
        wl = tmp_path / "custom.txt"
        wl.write_text("custom_payload_1\ncustom_payload_2\n# comment\n")

        count = gen.load_custom(PayloadCategory.SQLI, str(wl))
        assert count == 2

        payloads = gen.get(PayloadCategory.SQLI)
        values = [p.value for p in payloads]
        assert "custom_payload_1" in values
        assert "custom_payload_2" in values
