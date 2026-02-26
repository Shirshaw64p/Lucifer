"""
agents/base.py — AgentBrain Abstract Base Class
================================================
Defines the contract every agent brain must satisfy and provides
concrete infrastructure for:
  • ReAct loop execution (delegates to agents.react)
  • SQLite run-journal writes (thought / tool_call / observation)
  • ChromaDB per-agent memory load / save
  • Forced output on MAX_STEPS exhaustion
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, ClassVar, Dict, List, Optional, Type

import structlog
from pydantic import BaseModel

from agents.llm import LLMClient, get_llm

logger = structlog.get_logger("lucifer.agent.base")

# ---------------------------------------------------------------------------
# Journal DB path (SQLite) — configurable via env or default
# ---------------------------------------------------------------------------
_DEFAULT_JOURNAL_DB = Path("data/journals.sqlite3")


def _get_journal_path() -> Path:
    import os
    p = Path(os.environ.get("LUCIFER_JOURNAL_DB", str(_DEFAULT_JOURNAL_DB)))
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


def _ensure_journal_table(conn: sqlite3.Connection) -> None:
    conn.execute("""
        CREATE TABLE IF NOT EXISTS journal (
            id          TEXT PRIMARY KEY,
            run_id      TEXT NOT NULL,
            agent_type  TEXT NOT NULL,
            task_id     TEXT,
            step        INTEGER NOT NULL,
            entry_type  TEXT NOT NULL,
            content     TEXT NOT NULL,
            token_usage TEXT,
            created_at  TEXT NOT NULL
        )
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_journal_run
        ON journal(run_id, agent_type, step)
    """)
    conn.commit()


# ---------------------------------------------------------------------------
# ChromaDB Memory Helpers
# ---------------------------------------------------------------------------
def _get_chroma_client():
    """Lazy-load ChromaDB client (persistent storage)."""
    import os
    try:
        import chromadb
        persist_dir = os.environ.get("LUCIFER_CHROMA_DIR", "data/chromadb")
        Path(persist_dir).mkdir(parents=True, exist_ok=True)
        return chromadb.PersistentClient(path=persist_dir)
    except ImportError:
        logger.warning("chromadb_not_installed",
                       hint="pip install chromadb — memory disabled")
        return None


# ---------------------------------------------------------------------------
# AgentBrain ABC
# ---------------------------------------------------------------------------
class AgentBrain(ABC):
    """
    Abstract base class for all Lucifer agent brains.

    Subclasses MUST define the following class-level attributes and
    implement the three abstract methods.
    """

    # ---- Class-level attributes (must be overridden) -----------------------
    AGENT_TYPE: ClassVar[str] = ""
    LLM_MODEL: ClassVar[str] = ""
    SYSTEM_PROMPT: ClassVar[str] = ""
    MAX_STEPS: ClassVar[int] = 50
    TOKEN_BUDGET: ClassVar[int] = 100_000

    # Approval gate: tool names that require human approval before execution
    APPROVAL_REQUIRED_TOOLS: ClassVar[List[str]] = []

    # ---- Abstract methods ---------------------------------------------------

    @abstractmethod
    def get_tools(self) -> List[Dict[str, Any]]:
        """
        Return the list of tools available to this brain, formatted as
        OpenAI-compatible function-calling tool definitions.
        """
        ...

    @abstractmethod
    def get_input_schema(self) -> Type[BaseModel]:
        """Return the Pydantic model class for validated input."""
        ...

    @abstractmethod
    def get_output_schema(self) -> Type[BaseModel]:
        """Return the Pydantic model class for validated output."""
        ...

    # ---- Optional overrides ------------------------------------------------

    def pre_run_hook(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Hook called before the ReAct loop starts. Override to enrich context."""
        return context

    def post_run_hook(self, result: BaseModel, context: Dict[str, Any]) -> BaseModel:
        """Hook called after successful run. Override for post-processing."""
        return result

    # ---- Concrete run method -----------------------------------------------

    def run(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute the agent brain using the ReAct loop.

        Args:
            context: Must include at minimum:
                - run_id (str)
                - task_id (str)
                - target (str or dict)
                - scope (dict)
                Plus any brain-specific input fields.

        Returns:
            Validated output dict conforming to get_output_schema().
        """
        from agents.react import react_loop  # late import to avoid circular

        run_id = context.get("run_id", str(uuid.uuid4()))
        task_id = context.get("task_id", str(uuid.uuid4()))

        logger.info(
            "agent_run_start",
            agent_type=self.AGENT_TYPE,
            run_id=run_id,
            task_id=task_id,
            max_steps=self.MAX_STEPS,
            token_budget=self.TOKEN_BUDGET,
        )

        # Validate input
        input_cls = self.get_input_schema()
        validated_input = input_cls(**context)
        context = validated_input.model_dump()
        context["run_id"] = run_id
        context["task_id"] = task_id

        # Pre-run hook
        context = self.pre_run_hook(context)

        # Load memory
        memories = self.load_memory(run_id)
        if memories:
            context["_memories"] = memories

        # Get LLM client
        llm = get_llm(self.LLM_MODEL, fallback=True)

        # Execute ReAct loop
        result = react_loop(
            brain=self,
            llm=llm,
            context=context,
            run_id=run_id,
            task_id=task_id,
        )

        # Post-run hook
        result = self.post_run_hook(result, context)

        # Save to memory
        self.save_memory(run_id, result.model_dump() if isinstance(result, BaseModel) else result)

        # Log completion
        logger.info(
            "agent_run_complete",
            agent_type=self.AGENT_TYPE,
            run_id=run_id,
            task_id=task_id,
            token_usage=llm.get_usage_summary(),
        )

        return result.model_dump() if isinstance(result, BaseModel) else result

    # ---- Journal methods ---------------------------------------------------

    def write_journal(
        self,
        run_id: str,
        task_id: str,
        step: int,
        entry_type: str,
        content: Any,
        token_usage: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Append an entry to the SQLite run journal.

        entry_type is one of: 'thought', 'tool_call', 'observation',
        'error', 'forced_output', 'approval_request', 'approval_response'.
        """
        try:
            db_path = _get_journal_path()
            conn = sqlite3.connect(str(db_path))
            _ensure_journal_table(conn)

            entry_id = str(uuid.uuid4())
            content_str = json.dumps(content) if not isinstance(content, str) else content
            usage_str = json.dumps(token_usage) if token_usage else None
            now = datetime.now(timezone.utc).isoformat()

            conn.execute(
                """INSERT INTO journal
                   (id, run_id, agent_type, task_id, step, entry_type, content, token_usage, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (entry_id, run_id, self.AGENT_TYPE, task_id, step,
                 entry_type, content_str, usage_str, now),
            )
            conn.commit()
            conn.close()

            logger.debug(
                "journal_write",
                run_id=run_id,
                agent_type=self.AGENT_TYPE,
                step=step,
                entry_type=entry_type,
            )
        except Exception as exc:
            logger.error("journal_write_failed", error=str(exc), run_id=run_id)

    # ---- Memory methods (ChromaDB) ------------------------------------------

    def _memory_namespace(self) -> str:
        """Per-agent ChromaDB collection name."""
        return f"lucifer_memory_{self.AGENT_TYPE}"

    def load_memory(self, run_id: str, n_results: int = 10) -> List[Dict[str, Any]]:
        """
        Load relevant memories from ChromaDB for this agent.

        Queries the per-agent namespace with the run_id as context.
        Returns a list of memory documents (may be empty).
        """
        try:
            client = _get_chroma_client()
            if client is None:
                return []

            collection = client.get_or_create_collection(
                name=self._memory_namespace()
            )

            if collection.count() == 0:
                return []

            results = collection.query(
                query_texts=[f"run:{run_id} agent:{self.AGENT_TYPE}"],
                n_results=min(n_results, collection.count()),
            )

            memories = []
            if results and results.get("documents"):
                for doc_list in results["documents"]:
                    for doc in doc_list:
                        try:
                            memories.append(json.loads(doc))
                        except (json.JSONDecodeError, TypeError):
                            memories.append({"text": doc})

            logger.debug(
                "memory_loaded",
                agent_type=self.AGENT_TYPE,
                count=len(memories),
            )
            return memories

        except Exception as exc:
            logger.warning("memory_load_failed", error=str(exc))
            return []

    def save_memory(self, run_id: str, data: Any) -> None:
        """
        Persist agent output to ChromaDB under the per-agent namespace.

        Stores the full output as a document with run metadata.
        """
        try:
            client = _get_chroma_client()
            if client is None:
                return

            collection = client.get_or_create_collection(
                name=self._memory_namespace()
            )

            doc_id = f"{run_id}_{self.AGENT_TYPE}_{uuid.uuid4().hex[:8]}"
            doc_str = json.dumps(data) if not isinstance(data, str) else data
            metadata = {
                "run_id": run_id,
                "agent_type": self.AGENT_TYPE,
                "created_at": datetime.now(timezone.utc).isoformat(),
            }

            collection.add(
                ids=[doc_id],
                documents=[doc_str],
                metadatas=[metadata],
            )

            logger.debug(
                "memory_saved",
                agent_type=self.AGENT_TYPE,
                run_id=run_id,
                doc_id=doc_id,
            )

        except Exception as exc:
            logger.warning("memory_save_failed", error=str(exc))

    # ---- Representation ----------------------------------------------------

    def __repr__(self) -> str:
        return (
            f"<{self.__class__.__name__} type={self.AGENT_TYPE!r} "
            f"model={self.LLM_MODEL!r} max_steps={self.MAX_STEPS}>"
        )
