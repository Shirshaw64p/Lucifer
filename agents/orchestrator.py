"""
agents/orchestrator.py — LangGraph Stateful Orchestration Graph
================================================================
Implements the central run orchestrator as a LangGraph state machine.

Nodes:
    PLAN            → LLM call to produce task graph from engagement context
    DELEGATE        → Spawn agent brain as Celery task with context payload
    WAIT_FOR_REPORT → Poll DB for agent task completion
    APPROVAL_GATE   → Block on pending ApprovalEvent in DB
    ANALYZE         → LLM synthesises agent reports into consolidated findings
    COMPLETE        → Mark run complete, trigger Report Agent

State is persisted to PostgreSQL after every node transition for
crash-recovery.
"""

from __future__ import annotations

import json
import time
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Literal, Optional, Sequence, TypedDict

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger("lucifer.orchestrator")


# ---------------------------------------------------------------------------
# Graph State Schema
# ---------------------------------------------------------------------------
class TaskNode(BaseModel):
    """A single task in the task graph produced by PLAN."""
    task_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    agent_type: str
    depends_on: List[str] = Field(default_factory=list)
    priority: int = 1
    context_overrides: Dict[str, Any] = Field(default_factory=dict)
    status: str = "pending"  # pending | running | completed | failed
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    celery_task_id: Optional[str] = None


class ApprovalEvent(BaseModel):
    """An approval event that gates progress."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    run_id: str
    task_id: str
    agent_type: str
    tool_name: str
    arguments: Dict[str, Any] = Field(default_factory=dict)
    status: str = "pending"  # pending | approved | denied
    requested_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    decided_at: Optional[str] = None
    decided_by: Optional[str] = None


class Finding(BaseModel):
    """A security finding produced by analysis."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str
    severity: str  # critical | high | medium | low | informational
    cvss_score: Optional[float] = None
    description: str
    evidence: List[str] = Field(default_factory=list)
    remediation: str = ""
    agent_source: str = ""
    confidence: float = 0.0


class OrchestratorState(TypedDict, total=False):
    """Full state of the orchestrator graph — persisted after every transition."""
    run_id: str
    target: str
    scope: Dict[str, Any]
    engagement_config: Dict[str, Any]
    task_graph: List[Dict[str, Any]]  # serialised TaskNode list
    agent_results: Dict[str, Any]  # task_id → result
    findings: List[Dict[str, Any]]  # serialised Finding list
    pending_approvals: List[Dict[str, Any]]
    current_node: str
    status: str  # planning | delegating | waiting | approval_blocked | analyzing | complete | failed
    error: Optional[str]
    started_at: str
    completed_at: Optional[str]
    metadata: Dict[str, Any]


# ---------------------------------------------------------------------------
# State Persistence (PostgreSQL via SQLAlchemy)
# ---------------------------------------------------------------------------
class StatePersistence:
    """
    Persist orchestrator state to PostgreSQL after every node transition.
    Falls back to SQLite for local development.
    """

    def __init__(self) -> None:
        self._engine = None
        self._table_ensured = False

    def _get_connection(self):
        """Get a database connection (PostgreSQL preferred, SQLite fallback)."""
        import os
        import sqlite3

        pg_url = os.environ.get("LUCIFER_DATABASE_URL")
        if pg_url:
            try:
                from sqlalchemy import create_engine, text
                if self._engine is None:
                    self._engine = create_engine(pg_url)
                return self._engine
            except ImportError:
                logger.warning("sqlalchemy_not_available", hint="Falling back to SQLite")

        db_path = os.environ.get("LUCIFER_STATE_DB", "data/orchestrator_state.sqlite3")
        from pathlib import Path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        return sqlite3.connect(db_path)

    def _ensure_table(self, conn) -> None:
        """Create the state table if it doesn't exist."""
        if self._table_ensured:
            return

        import sqlite3
        if isinstance(conn, sqlite3.Connection):
            conn.execute("""
                CREATE TABLE IF NOT EXISTS orchestrator_state (
                    run_id      TEXT PRIMARY KEY,
                    state_json  TEXT NOT NULL,
                    node        TEXT NOT NULL,
                    status      TEXT NOT NULL,
                    updated_at  TEXT NOT NULL
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS orchestrator_state_history (
                    id          TEXT PRIMARY KEY,
                    run_id      TEXT NOT NULL,
                    node        TEXT NOT NULL,
                    state_json  TEXT NOT NULL,
                    created_at  TEXT NOT NULL
                )
            """)
            conn.commit()
        else:
            # SQLAlchemy engine for PostgreSQL
            from sqlalchemy import text
            with conn.begin() as txn:
                txn.execute(text("""
                    CREATE TABLE IF NOT EXISTS orchestrator_state (
                        run_id      TEXT PRIMARY KEY,
                        state_json  TEXT NOT NULL,
                        node        TEXT NOT NULL,
                        status      TEXT NOT NULL,
                        updated_at  TEXT NOT NULL
                    )
                """))
                txn.execute(text("""
                    CREATE TABLE IF NOT EXISTS orchestrator_state_history (
                        id          TEXT PRIMARY KEY,
                        run_id      TEXT NOT NULL,
                        node        TEXT NOT NULL,
                        state_json  TEXT NOT NULL,
                        created_at  TEXT NOT NULL
                    )
                """))

        self._table_ensured = True

    def save(self, state: OrchestratorState) -> None:
        """Persist current state (upsert + append to history)."""
        import sqlite3

        conn = self._get_connection()
        self._ensure_table(conn)

        run_id = state["run_id"]
        node = state.get("current_node", "unknown")
        status = state.get("status", "unknown")
        state_json = json.dumps(state, default=str)
        now = datetime.now(timezone.utc).isoformat()
        history_id = str(uuid.uuid4())

        if isinstance(conn, sqlite3.Connection):
            conn.execute(
                """INSERT OR REPLACE INTO orchestrator_state
                   (run_id, state_json, node, status, updated_at)
                   VALUES (?, ?, ?, ?, ?)""",
                (run_id, state_json, node, status, now),
            )
            conn.execute(
                """INSERT INTO orchestrator_state_history
                   (id, run_id, node, state_json, created_at)
                   VALUES (?, ?, ?, ?, ?)""",
                (history_id, run_id, node, state_json, now),
            )
            conn.commit()
            conn.close()
        else:
            from sqlalchemy import text
            with conn.begin() as txn:
                txn.execute(text("""
                    INSERT INTO orchestrator_state (run_id, state_json, node, status, updated_at)
                    VALUES (:run_id, :state_json, :node, :status, :now)
                    ON CONFLICT (run_id) DO UPDATE SET
                        state_json = :state_json, node = :node, status = :status, updated_at = :now
                """), {"run_id": run_id, "state_json": state_json,
                       "node": node, "status": status, "now": now})
                txn.execute(text("""
                    INSERT INTO orchestrator_state_history (id, run_id, node, state_json, created_at)
                    VALUES (:id, :run_id, :node, :state_json, :now)
                """), {"id": history_id, "run_id": run_id, "node": node,
                       "state_json": state_json, "now": now})

        logger.info(
            "state_persisted",
            run_id=run_id,
            node=node,
            status=status,
        )

    def load(self, run_id: str) -> Optional[OrchestratorState]:
        """Load the most recent state for a run (crash recovery)."""
        import sqlite3

        conn = self._get_connection()
        self._ensure_table(conn)

        if isinstance(conn, sqlite3.Connection):
            row = conn.execute(
                "SELECT state_json FROM orchestrator_state WHERE run_id = ?",
                (run_id,),
            ).fetchone()
            conn.close()
            if row:
                return json.loads(row[0])
        else:
            from sqlalchemy import text
            with conn.connect() as c:
                row = c.execute(
                    text("SELECT state_json FROM orchestrator_state WHERE run_id = :rid"),
                    {"rid": run_id},
                ).fetchone()
                if row:
                    return json.loads(row[0])

        return None


# Global persistence instance
_persistence = StatePersistence()


# ---------------------------------------------------------------------------
# Node Implementations
# ---------------------------------------------------------------------------
def node_plan(state: OrchestratorState) -> OrchestratorState:
    """
    PLAN node: LLM call with full context to produce a task graph.

    Analyses the target, scope, and engagement config to determine
    which agents to deploy and in what order.
    """
    from agents.llm import get_llm

    state["current_node"] = "PLAN"
    state["status"] = "planning"
    _persistence.save(state)

    llm = get_llm("claude-3-5-sonnet")

    # Import the registry to know available agent types
    from agents.registry import AGENT_REGISTRY
    available_agents = list(AGENT_REGISTRY.keys())

    plan_prompt = f"""You are the Lucifer orchestrator. Your job is to plan a penetration test.

## Target
{json.dumps(state.get('target', ''), default=str)}

## Scope
{json.dumps(state.get('scope', {}), indent=2, default=str)}

## Engagement Configuration
{json.dumps(state.get('engagement_config', {}), indent=2, default=str)}

## Available Agent Types
{json.dumps(available_agents)}

## Instructions
Produce a task graph as a JSON array of task objects. Each task has:
- "agent_type": one of the available agent types
- "depends_on": list of task IDs this task depends on (empty for root tasks)
- "priority": 1 (highest) to 5 (lowest)
- "context_overrides": any additional context specific to this task

Rules:
1. ALWAYS start with "recon" agent to map the attack surface.
2. Deploy specialized agents based on recon findings (use depends_on).
3. Always end with "evidence" agent to validate findings, then "report" agent.
4. Respect the scope — only include agents relevant to the engagement type.
5. The "knowledge" agent can run in parallel with other agents.

Return ONLY a JSON array of task objects, nothing else."""

    messages = [
        {"role": "system", "content": "You are an expert penetration test planner."},
        {"role": "user", "content": plan_prompt},
    ]

    try:
        response = llm.chat(messages=messages, temperature=0.1, max_tokens=4096)
        content = response.choices[0].message.content

        # Parse task graph from LLM response
        import re
        json_match = re.search(r'\[.*\]', content, re.DOTALL)
        if json_match:
            raw_tasks = json.loads(json_match.group(0))
        else:
            raw_tasks = json.loads(content)

        task_graph = []
        for i, raw in enumerate(raw_tasks):
            task = TaskNode(
                task_id=raw.get("task_id", f"task_{i:03d}_{raw.get('agent_type', 'unknown')}"),
                agent_type=raw["agent_type"],
                depends_on=raw.get("depends_on", []),
                priority=raw.get("priority", 3),
                context_overrides=raw.get("context_overrides", {}),
            )
            task_graph.append(task.model_dump())

        state["task_graph"] = task_graph
        logger.info("plan_complete", run_id=state["run_id"], task_count=len(task_graph))

    except Exception as exc:
        logger.error("plan_failed", error=str(exc))
        # Fallback: default task graph
        state["task_graph"] = _default_task_graph(state)
        logger.info("plan_fallback_used", run_id=state["run_id"])

    _persistence.save(state)
    return state


def _default_task_graph(state: OrchestratorState) -> List[Dict[str, Any]]:
    """Generate a sensible default task graph when LLM planning fails."""
    tasks = [
        TaskNode(task_id="task_000_recon", agent_type="recon", priority=1),
        TaskNode(task_id="task_001_knowledge", agent_type="knowledge", priority=2),
        TaskNode(task_id="task_002_web", agent_type="web", depends_on=["task_000_recon"], priority=2),
        TaskNode(task_id="task_003_injection", agent_type="injection", depends_on=["task_002_web"], priority=2),
        TaskNode(task_id="task_004_auth", agent_type="auth", depends_on=["task_000_recon"], priority=2),
        TaskNode(task_id="task_005_api", agent_type="api", depends_on=["task_000_recon"], priority=3),
        TaskNode(task_id="task_006_network", agent_type="network", depends_on=["task_000_recon"], priority=3),
        TaskNode(task_id="task_007_cloud", agent_type="cloud", depends_on=["task_000_recon"], priority=3),
        TaskNode(task_id="task_008_evidence", agent_type="evidence",
                 depends_on=["task_002_web", "task_003_injection", "task_004_auth",
                             "task_005_api", "task_006_network", "task_007_cloud"],
                 priority=4),
        TaskNode(task_id="task_009_report", agent_type="report",
                 depends_on=["task_008_evidence"], priority=5),
    ]
    return [t.model_dump() for t in tasks]


def node_delegate(state: OrchestratorState) -> OrchestratorState:
    """
    DELEGATE node: Spawn agent brains as Celery tasks.

    Identifies tasks whose dependencies are satisfied and dispatches them.
    """
    state["current_node"] = "DELEGATE"
    state["status"] = "delegating"
    _persistence.save(state)

    task_graph = [TaskNode(**t) for t in state.get("task_graph", [])]
    agent_results = state.get("agent_results", {})

    # Find tasks ready to run (dependencies satisfied)
    completed_ids = {tid for tid, res in agent_results.items() if res is not None}

    dispatched = 0
    for task in task_graph:
        if task.status != "pending":
            continue
        deps_met = all(dep_id in completed_ids for dep_id in task.depends_on)
        if not deps_met:
            continue

        # Build context payload
        context_payload = {
            "run_id": state["run_id"],
            "task_id": task.task_id,
            "target": state.get("target", ""),
            "scope": state.get("scope", {}),
            "agent_type": task.agent_type,
            **task.context_overrides,
        }

        # Inject dependency results into context
        for dep_id in task.depends_on:
            if dep_id in agent_results:
                context_payload[f"dep_{dep_id}"] = agent_results[dep_id]

        # Dispatch via Celery
        celery_task_id = _dispatch_celery_task(task.agent_type, context_payload)
        task.status = "running"
        task.celery_task_id = celery_task_id
        dispatched += 1

        logger.info(
            "task_dispatched",
            run_id=state["run_id"],
            task_id=task.task_id,
            agent_type=task.agent_type,
            celery_task_id=celery_task_id,
        )

    # Update task graph in state
    state["task_graph"] = [t.model_dump() for t in task_graph]
    logger.info("delegate_complete", run_id=state["run_id"], dispatched=dispatched)

    _persistence.save(state)
    return state


def _dispatch_celery_task(agent_type: str, context: Dict[str, Any]) -> str:
    """
    Dispatch an agent brain as a Celery task.

    Falls back to synchronous execution if Celery is not configured.
    """
    try:
        from core.celery_app import celery_app

        result = celery_app.send_task(
            "agents.tasks.run_agent",
            kwargs={"agent_type": agent_type, "context": context},
            queue="agents",
        )
        return result.id
    except (ImportError, Exception) as exc:
        logger.warning(
            "celery_dispatch_fallback",
            error=str(exc),
            hint="Running synchronously — install Celery for async dispatch",
        )
        # Synchronous fallback
        task_id = str(uuid.uuid4())
        try:
            from agents.registry import get_brain_class
            brain_cls = get_brain_class(agent_type)
            brain = brain_cls()
            brain.run(context)
        except Exception as run_exc:
            logger.error("sync_dispatch_failed", error=str(run_exc))
        return task_id


def node_wait_for_report(state: OrchestratorState) -> OrchestratorState:
    """
    WAIT_FOR_REPORT node: Poll DB for agent task completion.

    Checks each running task for completion status and collects results.
    """
    state["current_node"] = "WAIT_FOR_REPORT"
    state["status"] = "waiting"
    _persistence.save(state)

    task_graph = [TaskNode(**t) for t in state.get("task_graph", [])]
    agent_results = state.get("agent_results", {})

    poll_interval = 5  # seconds
    max_wait = 7200  # 2 hours
    elapsed = 0

    running_tasks = [t for t in task_graph if t.status == "running"]

    while running_tasks and elapsed < max_wait:
        for task in running_tasks:
            result = _poll_task_result(task.celery_task_id, task.task_id)
            if result is not None:
                task.status = "completed" if result.get("success", False) else "failed"
                task.result = result.get("data")
                task.error = result.get("error")
                agent_results[task.task_id] = task.result or {"error": task.error}

                logger.info(
                    "task_completed",
                    run_id=state["run_id"],
                    task_id=task.task_id,
                    agent_type=task.agent_type,
                    status=task.status,
                )

        running_tasks = [t for t in task_graph if t.status == "running"]

        if running_tasks:
            time.sleep(poll_interval)
            elapsed += poll_interval

            # Persist state periodically during wait
            state["task_graph"] = [t.model_dump() for t in task_graph]
            state["agent_results"] = agent_results
            _persistence.save(state)

    # Mark any still-running tasks as timed out
    for task in task_graph:
        if task.status == "running":
            task.status = "failed"
            task.error = "Timed out waiting for completion"
            agent_results[task.task_id] = {"error": task.error}
            logger.warning("task_timeout", task_id=task.task_id, agent_type=task.agent_type)

    state["task_graph"] = [t.model_dump() for t in task_graph]
    state["agent_results"] = agent_results

    _persistence.save(state)
    return state


def _poll_task_result(celery_task_id: Optional[str], task_id: str) -> Optional[Dict[str, Any]]:
    """
    Poll for task completion.

    Checks Celery result backend first, then falls back to DB polling.
    """
    if not celery_task_id:
        return None

    # Try Celery result backend
    try:
        from celery.result import AsyncResult
        from core.celery_app import celery_app

        result = AsyncResult(celery_task_id, app=celery_app)
        if result.ready():
            if result.successful():
                return {"success": True, "data": result.result}
            else:
                return {"success": False, "error": str(result.result)}
    except ImportError:
        pass

    # Fallback: check SQLite journal for completion markers
    try:
        import sqlite3
        import os
        from pathlib import Path

        db_path = Path(os.environ.get("LUCIFER_JOURNAL_DB", "data/journals.sqlite3"))
        if not db_path.exists():
            return None

        conn = sqlite3.connect(str(db_path))
        row = conn.execute(
            """SELECT content FROM journal
               WHERE task_id = ? AND entry_type = 'forced_output'
               ORDER BY created_at DESC LIMIT 1""",
            (task_id,),
        ).fetchone()
        conn.close()

        if row:
            return {"success": True, "data": json.loads(row[0])}
    except Exception:
        pass

    return None


def node_approval_gate(state: OrchestratorState) -> OrchestratorState:
    """
    APPROVAL_GATE node: Block on pending ApprovalEvents in DB.

    Checks for any unresolved approval requests and waits for decisions.
    """
    state["current_node"] = "APPROVAL_GATE"
    state["status"] = "approval_blocked"
    _persistence.save(state)

    pending = _get_pending_approvals(state["run_id"])

    if not pending:
        logger.info("no_pending_approvals", run_id=state["run_id"])
        return state

    logger.info(
        "approval_gate_blocking",
        run_id=state["run_id"],
        pending_count=len(pending),
    )

    poll_interval = 5
    max_wait = 3600  # 1 hour
    elapsed = 0

    while elapsed < max_wait:
        pending = _get_pending_approvals(state["run_id"])
        if not pending:
            break

        state["pending_approvals"] = [p.model_dump() for p in pending]
        _persistence.save(state)

        time.sleep(poll_interval)
        elapsed += poll_interval

    if pending:
        logger.warning(
            "approval_gate_timeout",
            run_id=state["run_id"],
            still_pending=len(pending),
        )

    state["pending_approvals"] = []
    _persistence.save(state)
    return state


def _get_pending_approvals(run_id: str) -> List[ApprovalEvent]:
    """Query DB for pending approval requests for this run."""
    try:
        import sqlite3
        import os
        from pathlib import Path

        db_path = Path(os.environ.get("LUCIFER_JOURNAL_DB", "data/journals.sqlite3"))
        if not db_path.exists():
            return []

        conn = sqlite3.connect(str(db_path))
        rows = conn.execute(
            """SELECT id, run_id, task_id, agent_type, tool_name, arguments, status, requested_at
               FROM approval_requests
               WHERE run_id = ? AND status = 'pending'""",
            (run_id,),
        ).fetchall()
        conn.close()

        events = []
        for row in rows:
            events.append(ApprovalEvent(
                id=row[0], run_id=row[1], task_id=row[2],
                agent_type=row[3], tool_name=row[4],
                arguments=json.loads(row[5]) if row[5] else {},
                status=row[6], requested_at=row[7] or "",
            ))
        return events

    except Exception as exc:
        logger.warning("approval_query_failed", error=str(exc))
        return []


def node_analyze(state: OrchestratorState) -> OrchestratorState:
    """
    ANALYZE node: LLM synthesises all agent reports into consolidated findings.
    """
    state["current_node"] = "ANALYZE"
    state["status"] = "analyzing"
    _persistence.save(state)

    from agents.llm import get_llm

    llm = get_llm("claude-3-5-sonnet")
    agent_results = state.get("agent_results", {})

    analyze_prompt = f"""You are the Lucifer analysis engine. Synthesise the following agent reports
into a consolidated list of security findings.

## Target
{json.dumps(state.get('target', ''), default=str)}

## Agent Reports
{json.dumps(agent_results, indent=2, default=str)}

## Instructions
For each distinct finding, produce a JSON object with:
- "title": concise finding title
- "severity": one of critical, high, medium, low, informational
- "cvss_score": CVSS 3.1 base score (0.0-10.0) or null
- "description": detailed technical description
- "evidence": list of evidence references (tool outputs, URLs, etc.)
- "remediation": actionable remediation steps
- "agent_source": which agent(s) discovered this
- "confidence": confidence level 0.0-1.0

Deduplicate findings across agents. Merge corroborating evidence.
Return ONLY a JSON array of finding objects."""

    messages = [
        {"role": "system", "content": "You are an expert security analyst synthesising pentest results."},
        {"role": "user", "content": analyze_prompt},
    ]

    try:
        response = llm.chat(messages=messages, temperature=0.1, max_tokens=8192)
        content = response.choices[0].message.content

        import re
        json_match = re.search(r'\[.*\]', content, re.DOTALL)
        if json_match:
            raw_findings = json.loads(json_match.group(0))
        else:
            raw_findings = json.loads(content)

        findings = []
        for raw in raw_findings:
            finding = Finding(
                title=raw.get("title", "Untitled Finding"),
                severity=raw.get("severity", "informational"),
                cvss_score=raw.get("cvss_score"),
                description=raw.get("description", ""),
                evidence=raw.get("evidence", []),
                remediation=raw.get("remediation", ""),
                agent_source=raw.get("agent_source", ""),
                confidence=raw.get("confidence", 0.5),
            )
            findings.append(finding.model_dump())

        state["findings"] = findings
        logger.info("analyze_complete", run_id=state["run_id"], finding_count=len(findings))

    except Exception as exc:
        logger.error("analyze_failed", error=str(exc))
        state["findings"] = state.get("findings", [])

    _persistence.save(state)
    return state


def node_complete(state: OrchestratorState) -> OrchestratorState:
    """
    COMPLETE node: Mark run complete and trigger the Report Agent.
    """
    state["current_node"] = "COMPLETE"
    state["status"] = "complete"
    state["completed_at"] = datetime.now(timezone.utc).isoformat()
    _persistence.save(state)

    # Trigger Report Agent with findings
    try:
        report_context = {
            "run_id": state["run_id"],
            "task_id": f"task_final_report_{state['run_id'][:8]}",
            "target": state.get("target", ""),
            "scope": state.get("scope", {}),
            "findings": state.get("findings", []),
            "agent_results": state.get("agent_results", {}),
            "engagement_config": state.get("engagement_config", {}),
        }

        celery_id = _dispatch_celery_task("report", report_context)
        logger.info(
            "report_agent_triggered",
            run_id=state["run_id"],
            celery_task_id=celery_id,
        )
    except Exception as exc:
        logger.error("report_agent_trigger_failed", error=str(exc))

    logger.info(
        "run_complete",
        run_id=state["run_id"],
        finding_count=len(state.get("findings", [])),
        duration_note="check started_at and completed_at",
    )

    _persistence.save(state)
    return state


# ---------------------------------------------------------------------------
# Edge / Routing Logic
# ---------------------------------------------------------------------------
def route_after_plan(state: OrchestratorState) -> str:
    """After PLAN, always go to DELEGATE."""
    task_graph = state.get("task_graph", [])
    if not task_graph:
        return "COMPLETE"
    return "DELEGATE"


def route_after_delegate(state: OrchestratorState) -> str:
    """After DELEGATE, go to WAIT_FOR_REPORT if tasks were dispatched."""
    task_graph = state.get("task_graph", [])
    running = [t for t in task_graph if t.get("status") == "running"]
    if running:
        return "WAIT_FOR_REPORT"
    return "ANALYZE"


def route_after_wait(state: OrchestratorState) -> str:
    """After WAIT, check for pending approvals or more tasks to delegate."""
    # Check for pending approvals
    pending_approvals = state.get("pending_approvals", [])
    if pending_approvals:
        return "APPROVAL_GATE"

    # Check if there are more pending tasks whose deps are now met
    task_graph = state.get("task_graph", [])
    agent_results = state.get("agent_results", {})
    completed_ids = set(agent_results.keys())

    pending_ready = [
        t for t in task_graph
        if t.get("status") == "pending"
        and all(d in completed_ids for d in t.get("depends_on", []))
    ]

    if pending_ready:
        return "DELEGATE"

    return "ANALYZE"


def route_after_approval(state: OrchestratorState) -> str:
    """After APPROVAL_GATE, re-enter WAIT or DELEGATE."""
    task_graph = state.get("task_graph", [])
    running = [t for t in task_graph if t.get("status") == "running"]
    if running:
        return "WAIT_FOR_REPORT"

    pending = [t for t in task_graph if t.get("status") == "pending"]
    if pending:
        return "DELEGATE"

    return "ANALYZE"


def route_after_analyze(state: OrchestratorState) -> str:
    """After ANALYZE, go to COMPLETE."""
    return "COMPLETE"


# ---------------------------------------------------------------------------
# LangGraph State Machine Construction
# ---------------------------------------------------------------------------
def build_orchestrator_graph():
    """
    Build and return the LangGraph StateGraph for the orchestrator.

    Returns:
        Compiled LangGraph graph ready for invocation.
    """
    try:
        from langgraph.graph import StateGraph, END
    except ImportError:
        logger.error(
            "langgraph_not_installed",
            hint="pip install langgraph — required for orchestrator",
        )
        raise ImportError("langgraph is required: pip install langgraph")

    graph = StateGraph(OrchestratorState)

    # Add nodes
    graph.add_node("PLAN", node_plan)
    graph.add_node("DELEGATE", node_delegate)
    graph.add_node("WAIT_FOR_REPORT", node_wait_for_report)
    graph.add_node("APPROVAL_GATE", node_approval_gate)
    graph.add_node("ANALYZE", node_analyze)
    graph.add_node("COMPLETE", node_complete)

    # Set entry point
    graph.set_entry_point("PLAN")

    # Add conditional edges
    graph.add_conditional_edges("PLAN", route_after_plan, {
        "DELEGATE": "DELEGATE",
        "COMPLETE": "COMPLETE",
    })
    graph.add_conditional_edges("DELEGATE", route_after_delegate, {
        "WAIT_FOR_REPORT": "WAIT_FOR_REPORT",
        "ANALYZE": "ANALYZE",
    })
    graph.add_conditional_edges("WAIT_FOR_REPORT", route_after_wait, {
        "APPROVAL_GATE": "APPROVAL_GATE",
        "DELEGATE": "DELEGATE",
        "ANALYZE": "ANALYZE",
    })
    graph.add_conditional_edges("APPROVAL_GATE", route_after_approval, {
        "WAIT_FOR_REPORT": "WAIT_FOR_REPORT",
        "DELEGATE": "DELEGATE",
        "ANALYZE": "ANALYZE",
    })
    graph.add_conditional_edges("ANALYZE", route_after_analyze, {
        "COMPLETE": "COMPLETE",
    })

    # COMPLETE is terminal
    graph.add_edge("COMPLETE", END)

    return graph.compile()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def start_run(
    target: str,
    scope: Dict[str, Any],
    engagement_config: Optional[Dict[str, Any]] = None,
    run_id: Optional[str] = None,
) -> OrchestratorState:
    """
    Start a new penetration test run.

    Creates initial state and invokes the orchestrator graph.

    Args:
        target:            Primary target (URL, IP, domain)
        scope:             Scope definition (allowed hosts, ports, methods)
        engagement_config: Optional config (depth, agent selection, etc.)
        run_id:            Optional pre-assigned run ID

    Returns:
        Final OrchestratorState after run completion.
    """
    rid = run_id or str(uuid.uuid4())

    initial_state: OrchestratorState = {
        "run_id": rid,
        "target": target,
        "scope": scope,
        "engagement_config": engagement_config or {},
        "task_graph": [],
        "agent_results": {},
        "findings": [],
        "pending_approvals": [],
        "current_node": "PLAN",
        "status": "planning",
        "error": None,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "completed_at": None,
        "metadata": {},
    }

    logger.info("run_starting", run_id=rid, target=target)
    _persistence.save(initial_state)

    try:
        graph = build_orchestrator_graph()
        final_state = graph.invoke(initial_state)
        return final_state
    except Exception as exc:
        logger.error("run_failed", run_id=rid, error=str(exc))
        initial_state["status"] = "failed"
        initial_state["error"] = str(exc)
        _persistence.save(initial_state)
        raise


def resume_run(run_id: str) -> OrchestratorState:
    """
    Resume a crashed or interrupted run from its last persisted state.

    Loads state from the DB and re-enters the graph at the appropriate node.
    """
    state = _persistence.load(run_id)
    if state is None:
        raise ValueError(f"No persisted state found for run_id={run_id}")

    logger.info(
        "run_resuming",
        run_id=run_id,
        last_node=state.get("current_node"),
        status=state.get("status"),
    )

    try:
        graph = build_orchestrator_graph()
        final_state = graph.invoke(state)
        return final_state
    except Exception as exc:
        logger.error("run_resume_failed", run_id=run_id, error=str(exc))
        state["status"] = "failed"
        state["error"] = str(exc)
        _persistence.save(state)
        raise
