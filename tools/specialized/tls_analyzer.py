"""
tools/specialized/tls_analyzer.py — TLS configuration analysis via sslyze.

Checks certificate validity, cipher suites, protocol versions,
and common TLS misconfigurations.
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from core.scope_guard import check_scope

logger = logging.getLogger(__name__)


@dataclass
class CertInfo:
    subject: str
    issuer: str
    not_before: str
    not_after: str
    serial: str
    san: List[str] = field(default_factory=list)
    is_self_signed: bool = False
    is_expired: bool = False


@dataclass
class TLSResult:
    host: str
    port: int
    certificate: Optional[CertInfo] = None
    supported_protocols: List[str] = field(default_factory=list)
    cipher_suites: List[str] = field(default_factory=list)
    vulnerabilities: List[str] = field(default_factory=list)
    is_secure: bool = True
    raw_output: Dict[str, Any] = field(default_factory=dict)


class TLSAnalyzer:
    """
    TLS/SSL analysis using sslyze.

    * ``analyze()``           — full TLS scan
    * ``check_certificate()`` — certificate chain validation only
    * ``check_protocols()``   — protocol & cipher enumeration
    """

    async def analyze(self, host: str, port: int = 443) -> TLSResult:
        """Full TLS analysis against *host*:*port*."""
        check_scope(host)

        result = TLSResult(host=host, port=port)

        try:
            from sslyze import (  # type: ignore[import-untyped]
                Scanner,
                ServerScanRequest,
                ServerNetworkLocation,
                ScanCommand,
            )

            location = ServerNetworkLocation(hostname=host, port=port)
            request = ServerScanRequest(
                server_location=location,
                scan_commands={
                    ScanCommand.CERTIFICATE_INFO,
                    ScanCommand.SSL_2_0_CIPHER_SUITES,
                    ScanCommand.SSL_3_0_CIPHER_SUITES,
                    ScanCommand.TLS_1_0_CIPHER_SUITES,
                    ScanCommand.TLS_1_1_CIPHER_SUITES,
                    ScanCommand.TLS_1_2_CIPHER_SUITES,
                    ScanCommand.TLS_1_3_CIPHER_SUITES,
                    ScanCommand.HEARTBLEED,
                    ScanCommand.ROBOT,
                    ScanCommand.TLS_COMPRESSION,
                },
            )

            scanner = Scanner()
            scanner.queue_scans([request])

            for scan_result in scanner.get_results():
                result = await asyncio.to_thread(
                    self._process_scan_result, scan_result, host, port
                )

        except ImportError:
            logger.warning("sslyze not installed — returning empty TLS result")
        except Exception as exc:
            logger.error("tls.analyze_error", extra={"error": str(exc)})

        return result

    def _process_scan_result(self, scan_result: Any, host: str, port: int) -> TLSResult:
        result = TLSResult(host=host, port=port)
        vulns: List[str] = []

        # Certificate
        try:
            cert_result = scan_result.scan_result.certificate_info
            if cert_result and cert_result.result:
                deployment = cert_result.result.certificate_deployments[0]
                leaf = deployment.received_certificate_chain[0]
                subject = leaf.subject.rfc4514_string()
                issuer = leaf.issuer.rfc4514_string()

                san_list: List[str] = []
                try:
                    from cryptography.x509.oid import ExtensionOID
                    san_ext = leaf.extensions.get_extension_for_oid(
                        ExtensionOID.SUBJECT_ALTERNATIVE_NAME
                    )
                    san_list = san_ext.value.get_values_for_type(
                        type(san_ext.value[0])  # type: ignore[arg-type]
                    ) if san_ext else []
                except Exception:
                    pass

                result.certificate = CertInfo(
                    subject=subject,
                    issuer=issuer,
                    not_before=str(leaf.not_valid_before_utc),
                    not_after=str(leaf.not_valid_after_utc),
                    serial=str(leaf.serial_number),
                    san=san_list,
                    is_self_signed=(subject == issuer),
                )
        except Exception:
            pass

        # Protocol / cipher enumeration
        proto_map = {
            "ssl_2_0_cipher_suites": "SSLv2",
            "ssl_3_0_cipher_suites": "SSLv3",
            "tls_1_0_cipher_suites": "TLSv1.0",
            "tls_1_1_cipher_suites": "TLSv1.1",
            "tls_1_2_cipher_suites": "TLSv1.2",
            "tls_1_3_cipher_suites": "TLSv1.3",
        }
        deprecated = {"SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"}

        for attr, proto_name in proto_map.items():
            try:
                cipher_result = getattr(scan_result.scan_result, attr, None)
                if cipher_result and cipher_result.result:
                    accepted = cipher_result.result.accepted_cipher_suites
                    if accepted:
                        result.supported_protocols.append(proto_name)
                        for cs in accepted:
                            result.cipher_suites.append(
                                f"{proto_name}: {cs.cipher_suite.name}"
                            )
                        if proto_name in deprecated:
                            vulns.append(f"Deprecated protocol supported: {proto_name}")
            except Exception:
                pass

        # Vulnerability checks
        try:
            hb = scan_result.scan_result.heartbleed
            if hb and hb.result and hb.result.is_vulnerable_to_heartbleed:
                vulns.append("Heartbleed (CVE-2014-0160)")
        except Exception:
            pass

        try:
            robot = scan_result.scan_result.robot
            if robot and robot.result:
                rr = robot.result.robot_result
                if "VULNERABLE" in str(rr):
                    vulns.append(f"ROBOT attack: {rr}")
        except Exception:
            pass

        try:
            comp = scan_result.scan_result.tls_compression
            if comp and comp.result and comp.result.supports_compression:
                vulns.append("TLS compression enabled (CRIME)")
        except Exception:
            pass

        result.vulnerabilities = vulns
        result.is_secure = len(vulns) == 0
        return result

    async def check_certificate(self, host: str, port: int = 443) -> Optional[CertInfo]:
        """Quick certificate-only check."""
        res = await self.analyze(host, port)
        return res.certificate

    async def check_protocols(self, host: str, port: int = 443) -> List[str]:
        """Return list of supported TLS/SSL protocol versions."""
        res = await self.analyze(host, port)
        return res.supported_protocols
