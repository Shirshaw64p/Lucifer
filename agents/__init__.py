"""
Lucifer Agent Brain Framework
==============================
Multi-agent orchestration system for autonomous penetration testing.

Modules:
    llm         - LiteLLM abstraction with fallback chains and token tracking
    base        - AgentBrain abstract base class
    react       - ReAct (Reasoning + Acting) loop engine
    orchestrator - LangGraph stateful orchestration graph
    registry    - Agent type → brain class mapping
    brains/     - Individual agent brain implementations
"""

from agents.registry import AGENT_REGISTRY, get_brain_class
from agents.llm import get_llm
from agents.base import AgentBrain

__all__ = [
    "AGENT_REGISTRY",
    "get_brain_class",
    "get_llm",
    "AgentBrain",
]
