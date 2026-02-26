"""
agents/llm.py — LiteLLM Abstraction Layer
==========================================
Provides a unified LLM interface with:
  • get_llm(model_name) factory function
  • Automatic fallback chain: Sonnet → GPT-4o → Ollama
  • Per-call token-usage tracking logged via structlog
  • Async and sync completion methods
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional, Sequence

import structlog
from litellm import acompletion, completion
from litellm.exceptions import (
    APIConnectionError,
    APIError,
    RateLimitError,
    ServiceUnavailableError,
    Timeout,
)
from pydantic import BaseModel

logger = structlog.get_logger("lucifer.llm")

# ---------------------------------------------------------------------------
# Model registry — canonical short names → LiteLLM model identifiers
# ---------------------------------------------------------------------------
MODELS: Dict[str, str] = {
    "claude-3-5-sonnet": "anthropic/claude-3-5-sonnet-20241022",
    "claude-3-5-haiku": "anthropic/claude-3-5-haiku-20241022",
    "gpt-4o": "openai/gpt-4o",
    "ollama/llama3.1": "ollama/llama3.1",
}

# Ordered fallback chain (primary → secondary → tertiary)
FALLBACK_CHAIN: List[str] = [
    "claude-3-5-sonnet",
    "gpt-4o",
    "ollama/llama3.1",
]

# Retryable exception types
_RETRYABLE = (RateLimitError, ServiceUnavailableError, APIConnectionError, Timeout)


# ---------------------------------------------------------------------------
# Token-usage dataclass
# ---------------------------------------------------------------------------
class TokenUsage(BaseModel):
    """Token usage record for a single LLM call."""
    model: str
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    latency_ms: float = 0.0
    cost_usd: float = 0.0


# ---------------------------------------------------------------------------
# Core LLM Client
# ---------------------------------------------------------------------------
class LLMClient:
    """
    Unified LLM client with:
    - Deterministic model resolution via MODELS registry
    - Automatic fallback across provider chain
    - Cumulative token tracking
    - structlog emission after every call
    """

    def __init__(self, model_name: str, *, fallback: bool = True) -> None:
        self.model_name = model_name
        self.model_id = MODELS.get(model_name, model_name)
        self.fallback_enabled = fallback
        # Cumulative counters
        self.total_prompt_tokens: int = 0
        self.total_completion_tokens: int = 0
        self.total_cost_usd: float = 0.0
        self.call_count: int = 0

    # ---- internal helpers ---------------------------------------------------

    def _build_fallback_chain(self) -> List[str]:
        """Return list of model IDs to try, starting with the primary."""
        chain = [self.model_id]
        if self.fallback_enabled:
            for name in FALLBACK_CHAIN:
                mid = MODELS[name]
                if mid != self.model_id and mid not in chain:
                    chain.append(mid)
        return chain

    def _log_usage(self, usage: TokenUsage) -> None:
        """Emit structured log with token usage metrics."""
        logger.info(
            "llm_call_complete",
            model=usage.model,
            prompt_tokens=usage.prompt_tokens,
            completion_tokens=usage.completion_tokens,
            total_tokens=usage.total_tokens,
            latency_ms=round(usage.latency_ms, 1),
            cost_usd=round(usage.cost_usd, 6),
            cumulative_prompt=self.total_prompt_tokens,
            cumulative_completion=self.total_completion_tokens,
            cumulative_cost=round(self.total_cost_usd, 6),
            call_number=self.call_count,
        )

    def _extract_usage(self, response: Any, model_id: str, latency_ms: float) -> TokenUsage:
        """Extract token usage from a LiteLLM response object."""
        usage_data = getattr(response, "usage", None)
        prompt_tok = getattr(usage_data, "prompt_tokens", 0) or 0
        comp_tok = getattr(usage_data, "completion_tokens", 0) or 0
        total_tok = prompt_tok + comp_tok

        # Attempt to grab cost from response metadata (LiteLLM provides this)
        cost = 0.0
        try:
            from litellm import completion_cost
            cost = completion_cost(completion_response=response) or 0.0
        except Exception:
            pass

        # Update cumulatives
        self.total_prompt_tokens += prompt_tok
        self.total_completion_tokens += comp_tok
        self.total_cost_usd += cost
        self.call_count += 1

        return TokenUsage(
            model=model_id,
            prompt_tokens=prompt_tok,
            completion_tokens=comp_tok,
            total_tokens=total_tok,
            latency_ms=latency_ms,
            cost_usd=cost,
        )

    # ---- synchronous completion ---------------------------------------------

    def chat(
        self,
        messages: List[Dict[str, Any]],
        *,
        tools: Optional[List[Dict[str, Any]]] = None,
        tool_choice: Optional[str | Dict] = None,
        temperature: float = 0.0,
        max_tokens: int = 4096,
        response_format: Optional[Dict] = None,
        **kwargs: Any,
    ) -> Any:
        """
        Synchronous chat completion with automatic fallback.

        Returns the full LiteLLM response object.
        Raises the last exception if all models in the chain fail.
        """
        chain = self._build_fallback_chain()
        last_exc: Optional[Exception] = None

        for model_id in chain:
            try:
                t0 = time.perf_counter()
                params: Dict[str, Any] = {
                    "model": model_id,
                    "messages": messages,
                    "temperature": temperature,
                    "max_tokens": max_tokens,
                    **kwargs,
                }
                if tools:
                    params["tools"] = tools
                if tool_choice is not None:
                    params["tool_choice"] = tool_choice
                if response_format is not None:
                    params["response_format"] = response_format

                response = completion(**params)
                latency = (time.perf_counter() - t0) * 1000

                usage = self._extract_usage(response, model_id, latency)
                self._log_usage(usage)
                return response

            except _RETRYABLE as exc:
                last_exc = exc
                logger.warning(
                    "llm_fallback_triggered",
                    failed_model=model_id,
                    error=str(exc),
                    remaining_models=chain[chain.index(model_id) + 1 :],
                )
                continue
            except (APIError,) as exc:
                last_exc = exc
                logger.error(
                    "llm_api_error",
                    model=model_id,
                    error=str(exc),
                )
                continue

        raise RuntimeError(
            f"All models in fallback chain exhausted. Last error: {last_exc}"
        )

    # ---- async completion ---------------------------------------------------

    async def achat(
        self,
        messages: List[Dict[str, Any]],
        *,
        tools: Optional[List[Dict[str, Any]]] = None,
        tool_choice: Optional[str | Dict] = None,
        temperature: float = 0.0,
        max_tokens: int = 4096,
        response_format: Optional[Dict] = None,
        **kwargs: Any,
    ) -> Any:
        """
        Async chat completion with automatic fallback.

        Returns the full LiteLLM response object.
        Raises the last exception if all models in the chain fail.
        """
        chain = self._build_fallback_chain()
        last_exc: Optional[Exception] = None

        for model_id in chain:
            try:
                t0 = time.perf_counter()
                params: Dict[str, Any] = {
                    "model": model_id,
                    "messages": messages,
                    "temperature": temperature,
                    "max_tokens": max_tokens,
                    **kwargs,
                }
                if tools:
                    params["tools"] = tools
                if tool_choice is not None:
                    params["tool_choice"] = tool_choice
                if response_format is not None:
                    params["response_format"] = response_format

                response = await acompletion(**params)
                latency = (time.perf_counter() - t0) * 1000

                usage = self._extract_usage(response, model_id, latency)
                self._log_usage(usage)
                return response

            except _RETRYABLE as exc:
                last_exc = exc
                logger.warning(
                    "llm_fallback_triggered_async",
                    failed_model=model_id,
                    error=str(exc),
                    remaining_models=chain[chain.index(model_id) + 1 :],
                )
                continue
            except (APIError,) as exc:
                last_exc = exc
                logger.error(
                    "llm_api_error_async",
                    model=model_id,
                    error=str(exc),
                )
                continue

        raise RuntimeError(
            f"All models in fallback chain exhausted (async). Last error: {last_exc}"
        )

    # ---- convenience helpers ------------------------------------------------

    def get_usage_summary(self) -> Dict[str, Any]:
        """Return cumulative token usage summary."""
        return {
            "model": self.model_name,
            "call_count": self.call_count,
            "total_prompt_tokens": self.total_prompt_tokens,
            "total_completion_tokens": self.total_completion_tokens,
            "total_tokens": self.total_prompt_tokens + self.total_completion_tokens,
            "total_cost_usd": round(self.total_cost_usd, 6),
        }

    def reset_counters(self) -> None:
        """Reset cumulative token counters."""
        self.total_prompt_tokens = 0
        self.total_completion_tokens = 0
        self.total_cost_usd = 0.0
        self.call_count = 0


# ---------------------------------------------------------------------------
# Public factory
# ---------------------------------------------------------------------------
def get_llm(model_name: str, *, fallback: bool = True) -> LLMClient:
    """
    Factory function — returns a configured LLMClient.

    Args:
        model_name: One of the canonical names in MODELS, or a raw
                    LiteLLM model string.
        fallback:   If True, auto-fallback through the chain on transient
                    errors (Sonnet → GPT-4o → Ollama).

    Returns:
        LLMClient instance ready for .chat() / .achat() calls.
    """
    if model_name not in MODELS:
        logger.warning("unknown_model_name", model_name=model_name,
                       hint="Using raw model string, fallback may not work as expected")
    return LLMClient(model_name, fallback=fallback)
