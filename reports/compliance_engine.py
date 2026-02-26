"""Compliance Engine — maps findings to regulatory framework controls.

Loads the compliance rules YAML and provides methods to:
- Map individual findings to controls across SOC 2, PCI-DSS, HIPAA, ISO 27001
- Generate a full pass/fail control matrix for a set of findings
- Export structured compliance data for report injection
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
from uuid import UUID

import yaml

from reports.models import (
    ComplianceMapping,
    ControlMatrix,
    ControlMatrixEntry,
    ControlStatus,
    FindingRecord,
    FrameworkControl,
)

logger = logging.getLogger(__name__)

_DEFAULT_RULES_PATH = Path(__file__).parent / "compliance_rules.yaml"

# The four supported frameworks and their YAML keys
FRAMEWORKS = ("soc2", "pci_dss", "hipaa", "iso27001")


class ComplianceEngine:
    """Maps vulnerability findings to compliance framework controls.

    Usage::

        engine = ComplianceEngine()
        engine.load_rules()                          # loads default YAML
        mapping = engine.map_finding(finding)         # single finding
        matrix  = engine.generate_control_matrix(findings)  # full matrix
        export  = engine.export_mapping(run_id)       # dict for report
    """

    def __init__(self) -> None:
        self._rules: Dict[str, Dict[str, List[Dict[str, str]]]] = {}
        self._loaded = False

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------

    def load_rules(self, yaml_path: Optional[str | Path] = None) -> Dict[str, Any]:
        """Load compliance rules from a YAML file.

        Args:
            yaml_path: Path to the YAML rules file.  Defaults to
                ``reports/compliance_rules.yaml``.

        Returns:
            The parsed rule set dictionary.
        """
        path = Path(yaml_path) if yaml_path else _DEFAULT_RULES_PATH
        with open(path, "r", encoding="utf-8") as fh:
            self._rules = yaml.safe_load(fh) or {}
        self._loaded = True
        logger.info("Loaded %d compliance rule categories from %s", len(self._rules), path)
        return self._rules

    @property
    def rules(self) -> Dict[str, Any]:
        if not self._loaded:
            self.load_rules()
        return self._rules

    # ------------------------------------------------------------------
    # Mapping a single finding
    # ------------------------------------------------------------------

    def map_finding(self, finding: FindingRecord) -> ComplianceMapping:
        """Map a single finding to all matching controls across all frameworks.

        The finding's ``vuln_category`` field is used for the lookup.
        If the category is not found in the rule set, an empty mapping is
        returned.
        """
        category = (finding.vuln_category or "").upper().strip()
        rule = self.rules.get(category, {})

        mapping = ComplianceMapping(
            finding_id=finding.id,
            vuln_category=category or "UNKNOWN",
        )

        for fw in FRAMEWORKS:
            controls: List[FrameworkControl] = []
            for ctrl_dict in rule.get(fw, []):
                controls.append(
                    FrameworkControl(
                        control_id=ctrl_dict["control_id"],
                        title=ctrl_dict.get("title", ""),
                        description=ctrl_dict.get("description", ""),
                    )
                )
            setattr(mapping, fw, controls)

        return mapping

    # ------------------------------------------------------------------
    # Full control matrix
    # ------------------------------------------------------------------

    def generate_control_matrix(
        self,
        findings: List[FindingRecord],
    ) -> ControlMatrix:
        """Build a pass/fail/partial matrix for every control across all frameworks.

        Logic:
        - A control is **FAIL** if at least one finding maps to it.
        - A control is **PASS** if it appears in the rules but no finding
          triggers it.
        - PARTIAL is not auto-assigned here but can be set by the caller
          if remediation is in-progress.

        Returns a :class:`ControlMatrix` with one entry per unique
        (framework, control_id) pair.
        """
        # First pass: collect all controls referenced by findings
        triggered: Dict[str, Dict[str, Set[UUID]]] = {fw: {} for fw in FRAMEWORKS}

        for finding in findings:
            mapping = self.map_finding(finding)
            for fw in FRAMEWORKS:
                for ctrl in getattr(mapping, fw):
                    triggered[fw].setdefault(ctrl.control_id, set()).add(finding.id)

        # Second pass: build entries for all controls in the full rule set
        seen: Set[str] = set()
        entries: List[ControlMatrixEntry] = []

        for category, rule in self.rules.items():
            for fw in FRAMEWORKS:
                for ctrl_dict in rule.get(fw, []):
                    key = f"{fw}::{ctrl_dict['control_id']}"
                    if key in seen:
                        # Might already exist — merge finding IDs
                        for entry in entries:
                            if entry.framework == fw and entry.control_id == ctrl_dict["control_id"]:
                                fids = triggered.get(fw, {}).get(ctrl_dict["control_id"], set())
                                for fid in fids:
                                    if fid not in entry.finding_ids:
                                        entry.finding_ids.append(fid)
                                if entry.finding_ids:
                                    entry.status = ControlStatus.FAIL
                                break
                        continue
                    seen.add(key)

                    fids = triggered.get(fw, {}).get(ctrl_dict["control_id"], set())
                    status = ControlStatus.FAIL if fids else ControlStatus.PASS
                    entries.append(
                        ControlMatrixEntry(
                            framework=fw,
                            control_id=ctrl_dict["control_id"],
                            title=ctrl_dict.get("title", ""),
                            status=status,
                            finding_ids=list(fids),
                        )
                    )

        return ControlMatrix(entries=entries)

    # ------------------------------------------------------------------
    # Export for report injection
    # ------------------------------------------------------------------

    def export_mapping(self, run_id: UUID, findings: Optional[List[FindingRecord]] = None) -> Dict[str, Any]:
        """Export structured compliance data for a given run.

        Returns a dictionary suitable for injecting into the
        :class:`ReportContent` model::

            {
                "run_id": "...",
                "per_finding": [ ComplianceMapping, ... ],
                "control_matrix": ControlMatrix,
            }
        """
        findings = findings or []
        per_finding = [self.map_finding(f) for f in findings]
        matrix = self.generate_control_matrix(findings)

        return {
            "run_id": str(run_id),
            "per_finding": [m.model_dump() for m in per_finding],
            "control_matrix": matrix.model_dump(),
        }
