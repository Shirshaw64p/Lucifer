"""
Lucifer Agent Brains Package
=============================
Each module implements a fully self-contained AgentBrain subclass
for a specific penetration-testing specialisation.
"""

from agents.brains.recon import ReconBrain
from agents.brains.web import WebBrain
from agents.brains.injection import InjectionBrain
from agents.brains.auth import AuthBrain
from agents.brains.api import APIBrain
from agents.brains.cloud import CloudBrain
from agents.brains.network import NetworkBrain
from agents.brains.evidence import EvidenceBrain
from agents.brains.knowledge import KnowledgeBrain
from agents.brains.report import ReportBrain

__all__ = [
    "ReconBrain",
    "WebBrain",
    "InjectionBrain",
    "AuthBrain",
    "APIBrain",
    "CloudBrain",
    "NetworkBrain",
    "EvidenceBrain",
    "KnowledgeBrain",
    "ReportBrain",
]
