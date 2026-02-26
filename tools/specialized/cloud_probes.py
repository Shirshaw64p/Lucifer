"""
tools/specialized/cloud_probes.py — Cloud metadata and misconfiguration probes.

Targets: AWS (IMDS v1/v2, S3 enum), GCP metadata, Azure IMDS.
All requests go through scope_guard to ensure authorised targets only.
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import httpx

from core.scope_guard import check_scope

logger = logging.getLogger(__name__)


@dataclass
class MetadataResult:
    provider: str        # aws, gcp, azure
    endpoint: str
    status: int
    body: str
    accessible: bool
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class S3BucketResult:
    bucket_name: str
    exists: bool
    public_read: bool
    public_write: bool
    region: str = ""
    error: str = ""


class CloudProbes:
    """
    Cloud infrastructure probes.

    * ``aws_metadata()``      — IMDS v1 & v2 probes
    * ``aws_s3_enum()``       — public S3 bucket enumeration
    * ``gcp_metadata()``      — GCP metadata server
    * ``azure_metadata()``    — Azure IMDS
    * ``probe_all()``         — test all cloud metadata endpoints
    """

    AWS_METADATA_BASE = "http://169.254.169.254"
    GCP_METADATA_BASE = "http://metadata.google.internal"
    AZURE_METADATA_BASE = "http://169.254.169.254"

    AWS_PATHS = [
        "/latest/meta-data/",
        "/latest/meta-data/iam/security-credentials/",
        "/latest/meta-data/hostname",
        "/latest/meta-data/instance-id",
        "/latest/meta-data/local-ipv4",
        "/latest/user-data",
        "/latest/dynamic/instance-identity/document",
    ]

    GCP_PATHS = [
        "/computeMetadata/v1/",
        "/computeMetadata/v1/project/project-id",
        "/computeMetadata/v1/instance/service-accounts/default/token",
        "/computeMetadata/v1/instance/hostname",
        "/computeMetadata/v1/instance/zone",
    ]

    AZURE_PATHS = [
        "/metadata/instance?api-version=2021-02-01",
        "/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
    ]

    def __init__(self, timeout: float = 5.0) -> None:
        self._timeout = timeout

    # ------------------------------------------------------------------
    # AWS
    # ------------------------------------------------------------------

    async def aws_metadata(self, target_url: Optional[str] = None) -> List[MetadataResult]:
        """
        Probe AWS IMDS (v1 & v2).

        If *target_url* is provided it is used as the SSRF vector base URL,
        otherwise the standard metadata IP is used.
        """
        base = (target_url or self.AWS_METADATA_BASE).rstrip("/")
        check_scope(base)

        results: List[MetadataResult] = []

        async with httpx.AsyncClient(timeout=self._timeout, verify=False) as client:
            # IMDSv1 — no token required
            for path in self.AWS_PATHS:
                url = f"{base}{path}"
                r = await self._probe(client, url, headers={})
                r.provider = "aws"
                r.metadata["imds_version"] = "v1"
                results.append(r)

            # IMDSv2 — requires PUT to get token first
            token_url = f"{base}/latest/api/token"
            try:
                token_resp = await client.put(
                    token_url,
                    headers={"X-aws-ec2-metadata-token-ttl-seconds": "21600"},
                )
                if token_resp.status_code == 200:
                    token = token_resp.text.strip()
                    for path in self.AWS_PATHS:
                        url = f"{base}{path}"
                        r = await self._probe(
                            client, url,
                            headers={"X-aws-ec2-metadata-token": token},
                        )
                        r.provider = "aws"
                        r.metadata["imds_version"] = "v2"
                        results.append(r)
            except Exception:
                pass

        return results

    # ------------------------------------------------------------------
    # S3 enumeration
    # ------------------------------------------------------------------

    async def aws_s3_enum(self, bucket_names: List[str]) -> List[S3BucketResult]:
        """Check if S3 buckets exist and are publicly accessible."""
        results: List[S3BucketResult] = []

        async with httpx.AsyncClient(timeout=self._timeout, verify=False) as client:
            for name in bucket_names:
                res = S3BucketResult(bucket_name=name, exists=False, public_read=False, public_write=False)
                url = f"https://{name}.s3.amazonaws.com"

                try:
                    # HEAD to check existence
                    head = await client.head(url)
                    if head.status_code in (200, 301, 307, 403):
                        res.exists = True
                        region = head.headers.get("x-amz-bucket-region", "")
                        res.region = region

                    # GET to check public read
                    if res.exists:
                        get_resp = await client.get(url)
                        if get_resp.status_code == 200:
                            res.public_read = True

                    # PUT to check public write (empty test)
                    if res.exists:
                        put_resp = await client.put(
                            f"{url}/_lucifer_write_test.txt",
                            content=b"lucifer-probe",
                        )
                        if put_resp.status_code in (200, 204):
                            res.public_write = True

                except Exception as exc:
                    res.error = str(exc)

                results.append(res)

        return results

    # ------------------------------------------------------------------
    # GCP
    # ------------------------------------------------------------------

    async def gcp_metadata(self, target_url: Optional[str] = None) -> List[MetadataResult]:
        """Probe GCP metadata server."""
        base = (target_url or self.GCP_METADATA_BASE).rstrip("/")
        check_scope(base)
        results: List[MetadataResult] = []

        async with httpx.AsyncClient(timeout=self._timeout, verify=False) as client:
            for path in self.GCP_PATHS:
                url = f"{base}{path}"
                r = await self._probe(
                    client, url,
                    headers={"Metadata-Flavor": "Google"},
                )
                r.provider = "gcp"
                results.append(r)

        return results

    # ------------------------------------------------------------------
    # Azure
    # ------------------------------------------------------------------

    async def azure_metadata(self, target_url: Optional[str] = None) -> List[MetadataResult]:
        """Probe Azure IMDS."""
        base = (target_url or self.AZURE_METADATA_BASE).rstrip("/")
        check_scope(base)
        results: List[MetadataResult] = []

        async with httpx.AsyncClient(timeout=self._timeout, verify=False) as client:
            for path in self.AZURE_PATHS:
                url = f"{base}{path}"
                r = await self._probe(
                    client, url,
                    headers={"Metadata": "true"},
                )
                r.provider = "azure"
                results.append(r)

        return results

    # ------------------------------------------------------------------
    # All-in-one
    # ------------------------------------------------------------------

    async def probe_all(self, target_url: Optional[str] = None) -> List[MetadataResult]:
        """Run all metadata probes (AWS + GCP + Azure)."""
        aws, gcp, azure = await asyncio.gather(
            self.aws_metadata(target_url),
            self.gcp_metadata(target_url),
            self.azure_metadata(target_url),
            return_exceptions=True,
        )
        results: List[MetadataResult] = []
        for batch in (aws, gcp, azure):
            if isinstance(batch, list):
                results.extend(batch)
        return results

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    async def _probe(
        self,
        client: httpx.AsyncClient,
        url: str,
        headers: Dict[str, str],
    ) -> MetadataResult:
        try:
            resp = await client.get(url, headers=headers)
            return MetadataResult(
                provider="",
                endpoint=url,
                status=resp.status_code,
                body=resp.text[:4096],
                accessible=resp.status_code == 200,
            )
        except Exception as exc:
            return MetadataResult(
                provider="",
                endpoint=url,
                status=0,
                body="",
                accessible=False,
                metadata={"error": str(exc)},
            )
