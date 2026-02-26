"""
agents/registry.py — Agent Brain Registry
==========================================
Maps agent_type string identifiers to their corresponding AgentBrain
subclass. Provides lookup and instantiation utilities.
"""

from __future__ import annotations

from typing import Dict, Optional, Type

import structlog

logger = structlog.get_logger("lucifer.registry")

# ---------------------------------------------------------------------------
# Registry dict — populated by imports below
# ---------------------------------------------------------------------------
AGENT_REGISTRY: Dict[str, Type] = {}


def _populate_registry() -> None:
    """Import all 10 brain modules and register them."""
    global AGENT_REGISTRY

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

    AGENT_REGISTRY.update({
        "recon": ReconBrain,
        "web": WebBrain,
        "injection": InjectionBrain,
        "auth": AuthBrain,
        "api": APIBrain,
        "cloud": CloudBrain,
        "network": NetworkBrain,
        "evidence": EvidenceBrain,
        "knowledge": KnowledgeBrain,
        "report": ReportBrain,
    })

    logger.info("agent_registry_populated", agent_count=len(AGENT_REGISTRY),
                agents=list(AGENT_REGISTRY.keys()))


# Populate on module load
try:
    _populate_registry()
except Exception as exc:
    logger.warning("agent_registry_partial_load", error=str(exc),
                   hint="Some brain modules may not be available yet")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def get_brain_class(agent_type: str) -> Type:
    """
    Look up a brain class by agent_type string.

    Args:
        agent_type: One of the registered agent type identifiers
                    (e.g., "recon", "web", "injection", etc.)

    Returns:
        The AgentBrain subclass for the given type.

    Raises:
        KeyError: If agent_type is not registered.
    """
    if agent_type not in AGENT_REGISTRY:
        # Try lazy re-population in case modules were added after init
        try:
            _populate_registry()
        except Exception:
            pass

    if agent_type not in AGENT_REGISTRY:
        available = list(AGENT_REGISTRY.keys())
        raise KeyError(
            f"Unknown agent_type '{agent_type}'. "
            f"Available types: {available}"
        )

    return AGENT_REGISTRY[agent_type]


def register_brain(agent_type: str, brain_class: Type) -> None:
    """
    Register a new brain class (for plugins / extensions).

    Args:
        agent_type:  Unique string identifier
        brain_class: AgentBrain subclass
    """
    if agent_type in AGENT_REGISTRY:
        logger.warning("agent_registry_overwrite", agent_type=agent_type)

    AGENT_REGISTRY[agent_type] = brain_class
    logger.info("agent_registered", agent_type=agent_type,
                brain_class=brain_class.__name__)


def list_agents() -> Dict[str, str]:
    """Return dict of {agent_type: brain_class_name}."""
    return {k: v.__name__ for k, v in AGENT_REGISTRY.items()}
