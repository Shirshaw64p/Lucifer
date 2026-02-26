"""
Tests for tools/specialized/jwt_toolkit.py — JWTToolkit.

No external services — pure local crypto.
"""
from __future__ import annotations

import base64
import json

import pytest

from tools.specialized.jwt_toolkit import JWTToolkit


def _make_token(header: dict, payload: dict, signature: str = "fakesig") -> str:
    """Build a minimal JWT for testing."""
    h = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode()
    p = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    return f"{h}.{p}.{signature}"


@pytest.fixture
def toolkit() -> JWTToolkit:
    return JWTToolkit()


class TestJWTDecode:
    def test_decode_valid_token(self, toolkit: JWTToolkit) -> None:
        token = _make_token({"alg": "HS256", "typ": "JWT"}, {"sub": "1234", "admin": True})
        analysis = toolkit.decode(token)

        assert analysis.header["alg"] == "HS256"
        assert analysis.payload["sub"] == "1234"
        assert analysis.payload["admin"] is True

    def test_decode_invalid_format(self, toolkit: JWTToolkit) -> None:
        with pytest.raises(ValueError, match="Invalid JWT format"):
            toolkit.decode("not.a.valid.jwt.token.extra")

    def test_decode_two_parts_raises(self, toolkit: JWTToolkit) -> None:
        with pytest.raises(ValueError):
            toolkit.decode("header.payload")


class TestJWTAlgNone:
    def test_alg_none_produces_forged_tokens(self, toolkit: JWTToolkit) -> None:
        token = _make_token({"alg": "HS256"}, {"sub": "1234"})
        analysis = toolkit.test_alg_none(token)

        assert len(analysis.forged_tokens) == 4  # none, None, NONE, nOnE
        for ft in analysis.forged_tokens:
            assert ft.endswith(".")  # empty signature
        assert any("alg:none" in v for v in analysis.vulnerabilities)


class TestJWTBruteSecret:
    def test_brute_finds_weak_secret(self, toolkit: JWTToolkit) -> None:
        """When pyjwt is available, test brute-forcing."""
        try:
            import jwt as pyjwt
        except ImportError:
            pytest.skip("pyjwt not installed")

        token = pyjwt.encode({"sub": "1234"}, "secret", algorithm="HS256")
        analysis = toolkit.brute_secret(token)

        assert analysis.cracked_secret == "secret"
        assert any("Weak HMAC" in v for v in analysis.vulnerabilities)

    def test_brute_does_not_find_strong_secret(self, toolkit: JWTToolkit) -> None:
        try:
            import jwt as pyjwt
        except ImportError:
            pytest.skip("pyjwt not installed")

        token = pyjwt.encode({"sub": "1234"}, "xK9$mZ!vQ2rT7wL0", algorithm="HS256")
        analysis = toolkit.brute_secret(token)

        assert analysis.cracked_secret is None


class TestJWTFullAnalysis:
    def test_full_analysis_aggregates(self, toolkit: JWTToolkit) -> None:
        token = _make_token({"alg": "HS256"}, {"sub": "1234", "exp": 0})
        analysis = toolkit.full_analysis(token)

        assert len(analysis.vulnerabilities) >= 1
        assert len(analysis.forged_tokens) >= 1
