"""
agents/react.py — ReAct Loop Engine
====================================
Implements the Reasoning + Acting loop for all Lucifer agent brains.

Flow per iteration:
    1. THOUGHT  — LLM reasons about current state
    2. ACTION   — LLM selects a tool and parameters
    3. VALIDATE — Pydantic validation of tool call parameters
    4. SCOPE    — Route through scope_guard before execution
    5. APPROVAL — If tool is high-risk, emit ApprovalRequest and block
    6. EXECUTE  — Run the tool and capture result
    7. OBSERVE  — Feed observation back into context

Hard-stop at MAX_STEPS with forced output generation.
"""

from __future__ import annotations

import json
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Type

import structlog
from pydantic import BaseModel, ValidationError

from agents.llm import LLMClient

logger = structlog.get_logger("lucifer.react")


# ---------------------------------------------------------------------------
# Pydantic models for ReAct loop messages
# ---------------------------------------------------------------------------
class ToolCallRequest(BaseModel):
    """Represents a tool call the LLM wants to make."""
    tool_name: str
    arguments: Dict[str, Any]


class ToolCallResult(BaseModel):
    """Result of executing a tool."""
    tool_name: str
    success: bool
    result: Any = None
    error: Optional[str] = None
    execution_time_ms: float = 0.0


class ApprovalRequest(BaseModel):
    """Request for human approval of a high-risk tool call."""
    id: str
    run_id: str
    task_id: str
    agent_type: str
    tool_name: str
    arguments: Dict[str, Any]
    reason: str
    requested_at: str
    status: str = "pending"  # pending | approved | denied


# ---------------------------------------------------------------------------
# Scope Guard Integration
# ---------------------------------------------------------------------------
class ScopeViolationError(Exception):
    """Raised when a tool call violates the defined scope."""
    pass


def _check_scope_guard(tool_name: str, arguments: Dict[str, Any], scope: Dict[str, Any]) -> bool:
    """
    Route tool call through scope_guard.

    Attempts to import and use tools.scope_guard.check_scope().
    If the module is not available, logs a warning and allows execution
    (fail-open for development; MUST be fail-closed in production).
    """
    try:
        from tools.scope_guard import check_scope
        return check_scope(tool_name=tool_name, arguments=arguments, scope=scope)
    except ImportError:
        logger.warning(
            "scope_guard_not_available",
            hint="tools.scope_guard module not found — allowing execution (dev mode)",
            tool_name=tool_name,
        )
        return True
    except Exception as exc:
        logger.error("scope_guard_error", tool_name=tool_name, error=str(exc))
        raise ScopeViolationError(f"Scope guard error for {tool_name}: {exc}")


# ---------------------------------------------------------------------------
# Approval Gate
# ---------------------------------------------------------------------------
def _check_approval_gate(
    tool_name: str,
    arguments: Dict[str, Any],
    run_id: str,
    task_id: str,
    agent_type: str,
    approval_required_tools: List[str],
) -> bool:
    """
    If the tool is flagged high-risk, emit an ApprovalRequest to the DB
    and block until a decision (approved/denied) arrives.

    Returns True if approved (or no approval needed), False if denied.
    """
    if tool_name not in approval_required_tools:
        return True

    approval_id = str(uuid.uuid4())
    request = ApprovalRequest(
        id=approval_id,
        run_id=run_id,
        task_id=task_id,
        agent_type=agent_type,
        tool_name=tool_name,
        arguments=arguments,
        reason=f"Tool '{tool_name}' requires human approval before execution",
        requested_at=datetime.now(timezone.utc).isoformat(),
    )

    logger.info(
        "approval_request_emitted",
        approval_id=approval_id,
        tool_name=tool_name,
        agent_type=agent_type,
        run_id=run_id,
    )

    # Persist to DB and poll for decision
    try:
        return _persist_and_poll_approval(request)
    except Exception as exc:
        logger.error("approval_gate_error", error=str(exc))
        return False  # fail-closed


def _persist_and_poll_approval(request: ApprovalRequest, timeout_seconds: int = 3600) -> bool:
    """
    Write ApprovalRequest to the database and poll until status changes.

    Uses SQLite journal DB for portability. Production should use
    PostgreSQL via core.db.
    """
    import sqlite3
    from pathlib import Path
    import os

    db_path = Path(os.environ.get("LUCIFER_JOURNAL_DB", "data/journals.sqlite3"))
    db_path.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(str(db_path))
    conn.execute("""
        CREATE TABLE IF NOT EXISTS approval_requests (
            id           TEXT PRIMARY KEY,
            run_id       TEXT NOT NULL,
            task_id      TEXT NOT NULL,
            agent_type   TEXT NOT NULL,
            tool_name    TEXT NOT NULL,
            arguments    TEXT NOT NULL,
            reason       TEXT NOT NULL,
            requested_at TEXT NOT NULL,
            status       TEXT NOT NULL DEFAULT 'pending',
            decided_at   TEXT,
            decided_by   TEXT
        )
    """)
    conn.execute(
        """INSERT INTO approval_requests
           (id, run_id, task_id, agent_type, tool_name, arguments, reason, requested_at, status)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            request.id, request.run_id, request.task_id, request.agent_type,
            request.tool_name, json.dumps(request.arguments),
            request.reason, request.requested_at, "pending",
        ),
    )
    conn.commit()

    # Poll for decision
    poll_interval = 2  # seconds
    elapsed = 0
    while elapsed < timeout_seconds:
        row = conn.execute(
            "SELECT status FROM approval_requests WHERE id = ?",
            (request.id,),
        ).fetchone()

        if row and row[0] in ("approved", "denied"):
            conn.close()
            decision = row[0]
            logger.info(
                "approval_decision_received",
                approval_id=request.id,
                decision=decision,
                waited_seconds=elapsed,
            )
            return decision == "approved"

        time.sleep(poll_interval)
        elapsed += poll_interval

    # Timeout — deny by default
    conn.close()
    logger.warning(
        "approval_timeout",
        approval_id=request.id,
        timeout_seconds=timeout_seconds,
    )
    return False


# ---------------------------------------------------------------------------
# Tool Executor
# ---------------------------------------------------------------------------
def _execute_tool(tool_name: str, arguments: Dict[str, Any]) -> ToolCallResult:
    """
    Execute a tool by name with given arguments.

    Looks up the tool in the global tool registry and invokes it.
    """
    t0 = time.perf_counter()
    try:
        # Attempt to import tool registry from platform core
        try:
            from tools.registry import get_tool
            tool_fn = get_tool(tool_name)
        except ImportError:
            # Fallback: try to find tool in a dynamic registry
            tool_fn = _get_tool_from_fallback_registry(tool_name)

        if tool_fn is None:
            return ToolCallResult(
                tool_name=tool_name,
                success=False,
                error=f"Tool '{tool_name}' not found in registry",
                execution_time_ms=(time.perf_counter() - t0) * 1000,
            )

        result = tool_fn(**arguments)
        elapsed = (time.perf_counter() - t0) * 1000

        return ToolCallResult(
            tool_name=tool_name,
            success=True,
            result=result,
            execution_time_ms=elapsed,
        )

    except Exception as exc:
        elapsed = (time.perf_counter() - t0) * 1000
        logger.error(
            "tool_execution_failed",
            tool_name=tool_name,
            error=str(exc),
        )
        return ToolCallResult(
            tool_name=tool_name,
            success=False,
            error=str(exc),
            execution_time_ms=elapsed,
        )


def _get_tool_from_fallback_registry(tool_name: str):
    """Fallback tool lookup when platform core is not available."""
    # This will be populated by the tool registry module
    _FALLBACK_TOOLS: Dict[str, Any] = {}
    return _FALLBACK_TOOLS.get(tool_name)


# ---------------------------------------------------------------------------
# Message Construction Helpers
# ---------------------------------------------------------------------------
def _build_system_message(brain, context: Dict[str, Any]) -> Dict[str, str]:
    """Build the system message with brain's prompt and context injection."""
    memories_section = ""
    if context.get("_memories"):
        mem_text = json.dumps(context["_memories"], indent=2, default=str)
        memories_section = f"\n\n## Relevant Memories from Previous Runs\n{mem_text}"

    scope_section = ""
    if context.get("scope"):
        scope_text = json.dumps(context["scope"], indent=2, default=str)
        scope_section = f"\n\n## Engagement Scope\n{scope_text}"

    system_content = (
        f"{brain.SYSTEM_PROMPT}"
        f"{scope_section}"
        f"{memories_section}"
        f"\n\n## Rules\n"
        f"- You MUST stay within the defined scope at all times.\n"
        f"- You have a maximum of {brain.MAX_STEPS} steps. Use them wisely.\n"
        f"- When you have gathered enough information to produce your final output, "
        f"call the 'submit_output' function with your complete findings.\n"
        f"- Every tool call must include valid parameters.\n"
        f"- If a tool fails, retry with adjusted parameters or move to alternatives.\n"
        f"- Document every significant finding in your reasoning.\n"
    )
    return {"role": "system", "content": system_content}


def _build_initial_user_message(context: Dict[str, Any]) -> Dict[str, str]:
    """Build the initial user message from the context payload."""
    # Filter out internal fields
    filtered = {k: v for k, v in context.items() if not k.startswith("_")}
    return {
        "role": "user",
        "content": (
            f"Execute your assigned task with the following context:\n\n"
            f"```json\n{json.dumps(filtered, indent=2, default=str)}\n```\n\n"
            f"Begin your analysis. Think step by step."
        ),
    }


def _build_submit_tool() -> Dict[str, Any]:
    """Build the special 'submit_output' tool definition."""
    return {
        "type": "function",
        "function": {
            "name": "submit_output",
            "description": (
                "Submit your final output when you have completed the task. "
                "The output must conform to the required output schema."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "output": {
                        "type": "object",
                        "description": "The complete output conforming to the output schema.",
                    }
                },
                "required": ["output"],
            },
        },
    }


# ---------------------------------------------------------------------------
# ReAct Loop — Main Entry Point
# ---------------------------------------------------------------------------
def react_loop(
    brain,
    llm: LLMClient,
    context: Dict[str, Any],
    run_id: str,
    task_id: str,
) -> BaseModel:
    """
    Execute the ReAct (Reasoning + Acting) loop for an agent brain.

    Args:
        brain:   AgentBrain instance with tools, prompts, schemas defined
        llm:     Configured LLMClient
        context: Full execution context (validated input + metadata)
        run_id:  Run identifier
        task_id: Task identifier

    Returns:
        Pydantic model instance conforming to brain.get_output_schema()
    """
    output_schema = brain.get_output_schema()
    tools = brain.get_tools() + [_build_submit_tool()]
    scope = context.get("scope", {})

    # Build initial messages
    messages: List[Dict[str, Any]] = [
        _build_system_message(brain, context),
        _build_initial_user_message(context),
    ]

    step = 0
    final_output: Optional[BaseModel] = None

    logger.info(
        "react_loop_start",
        agent_type=brain.AGENT_TYPE,
        run_id=run_id,
        max_steps=brain.MAX_STEPS,
    )

    while step < brain.MAX_STEPS:
        step += 1

        # Check token budget
        if llm.total_prompt_tokens + llm.total_completion_tokens >= brain.TOKEN_BUDGET:
            logger.warning(
                "token_budget_exhausted",
                agent_type=brain.AGENT_TYPE,
                run_id=run_id,
                step=step,
                tokens_used=llm.total_prompt_tokens + llm.total_completion_tokens,
            )
            break

        # ----- THOUGHT + ACTION: LLM call ---------------------------------
        try:
            response = llm.chat(
                messages=messages,
                tools=tools,
                temperature=0.0,
                max_tokens=4096,
            )
        except Exception as exc:
            logger.error(
                "react_llm_call_failed",
                step=step,
                error=str(exc),
            )
            brain.write_journal(run_id, task_id, step, "error",
                                {"error": str(exc), "phase": "llm_call"})
            break

        choice = response.choices[0]
        message = choice.message

        # Extract thought (content) if present
        thought = message.content or ""
        if thought:
            brain.write_journal(run_id, task_id, step, "thought", thought)
            logger.debug("react_thought", step=step, thought=thought[:200])

        # No tool calls → agent wants to finish with text
        if not message.tool_calls:
            messages.append({"role": "assistant", "content": thought})
            # Try to parse the text response as output
            final_output = _try_parse_output(thought, output_schema, brain, run_id, task_id, step)
            if final_output:
                break
            # If can't parse, prompt agent to use submit_output tool
            messages.append({
                "role": "user",
                "content": (
                    "You must submit your final output using the submit_output tool. "
                    "Please call submit_output with your complete findings."
                ),
            })
            continue

        # Append assistant message with tool calls to history
        messages.append(message.model_dump())

        # ----- Process each tool call --------------------------------------
        for tool_call in message.tool_calls:
            tc_id = tool_call.id
            fn = tool_call.function
            tool_name = fn.name
            raw_args = fn.arguments

            # Parse arguments
            try:
                arguments = json.loads(raw_args) if isinstance(raw_args, str) else raw_args
            except json.JSONDecodeError:
                arguments = {}

            logger.debug(
                "react_action",
                step=step,
                tool=tool_name,
                args_preview=str(arguments)[:200],
            )

            # Check for submit_output
            if tool_name == "submit_output":
                output_data = arguments.get("output", arguments)
                brain.write_journal(run_id, task_id, step, "tool_call",
                                    {"tool": "submit_output", "data": output_data})
                try:
                    final_output = output_schema(**output_data)
                    messages.append({
                        "role": "tool",
                        "tool_call_id": tc_id,
                        "content": json.dumps({"status": "accepted", "message": "Output submitted successfully."}),
                    })
                    brain.write_journal(run_id, task_id, step, "observation",
                                        {"tool": "submit_output", "status": "accepted"})
                except ValidationError as ve:
                    error_msg = f"Output validation failed: {ve}"
                    messages.append({
                        "role": "tool",
                        "tool_call_id": tc_id,
                        "content": json.dumps({"status": "rejected", "error": error_msg}),
                    })
                    brain.write_journal(run_id, task_id, step, "error",
                                        {"tool": "submit_output", "error": error_msg})
                    logger.warning("react_output_validation_failed", step=step, error=error_msg)
                continue

            # ----- VALIDATE: Pydantic validation of tool parameters ----------
            tool_call_obj = ToolCallRequest(tool_name=tool_name, arguments=arguments)
            brain.write_journal(run_id, task_id, step, "tool_call",
                                {"tool": tool_name, "arguments": arguments})

            # ----- SCOPE: Route through scope_guard --------------------------
            try:
                scope_ok = _check_scope_guard(tool_name, arguments, scope)
                if not scope_ok:
                    error_msg = f"Scope violation: tool '{tool_name}' with given arguments is out of scope."
                    messages.append({
                        "role": "tool",
                        "tool_call_id": tc_id,
                        "content": json.dumps({"error": error_msg}),
                    })
                    brain.write_journal(run_id, task_id, step, "error",
                                        {"tool": tool_name, "error": "scope_violation"})
                    continue
            except ScopeViolationError as sve:
                messages.append({
                    "role": "tool",
                    "tool_call_id": tc_id,
                    "content": json.dumps({"error": str(sve)}),
                })
                brain.write_journal(run_id, task_id, step, "error",
                                    {"tool": tool_name, "error": str(sve)})
                continue

            # ----- APPROVAL: Check approval gate for high-risk tools ---------
            if not _check_approval_gate(
                tool_name=tool_name,
                arguments=arguments,
                run_id=run_id,
                task_id=task_id,
                agent_type=brain.AGENT_TYPE,
                approval_required_tools=brain.APPROVAL_REQUIRED_TOOLS,
            ):
                denial_msg = f"Tool '{tool_name}' was denied approval. Skipping."
                messages.append({
                    "role": "tool",
                    "tool_call_id": tc_id,
                    "content": json.dumps({"error": denial_msg, "status": "denied"}),
                })
                brain.write_journal(run_id, task_id, step, "approval_response",
                                    {"tool": tool_name, "decision": "denied"})
                continue

            # ----- EXECUTE: Run the tool ------------------------------------
            result = _execute_tool(tool_name, arguments)

            # ----- OBSERVE: Feed result back --------------------------------
            observation = {
                "tool": tool_name,
                "success": result.success,
                "result": result.result,
                "error": result.error,
                "execution_time_ms": result.execution_time_ms,
            }

            messages.append({
                "role": "tool",
                "tool_call_id": tc_id,
                "content": json.dumps(observation, default=str),
            })

            brain.write_journal(run_id, task_id, step, "observation", observation)

            logger.debug(
                "react_observation",
                step=step,
                tool=tool_name,
                success=result.success,
                exec_time_ms=round(result.execution_time_ms, 1),
            )

        # If we got final output from submit_output, break
        if final_output is not None:
            break

    # ----- MAX_STEPS reached or token budget exhausted: force output --------
    if final_output is None:
        logger.warning(
            "react_forced_output",
            agent_type=brain.AGENT_TYPE,
            run_id=run_id,
            steps_used=step,
        )
        final_output = _force_output(
            brain=brain,
            llm=llm,
            messages=messages,
            output_schema=output_schema,
            run_id=run_id,
            task_id=task_id,
            step=step,
        )

    logger.info(
        "react_loop_complete",
        agent_type=brain.AGENT_TYPE,
        run_id=run_id,
        steps_used=step,
        token_usage=llm.get_usage_summary(),
    )

    return final_output


# ---------------------------------------------------------------------------
# Forced Output Generation
# ---------------------------------------------------------------------------
def _force_output(
    brain,
    llm: LLMClient,
    messages: List[Dict[str, Any]],
    output_schema: Type[BaseModel],
    run_id: str,
    task_id: str,
    step: int,
) -> BaseModel:
    """
    Force the LLM to produce a final output conforming to the schema.
    Called when MAX_STEPS is reached or token budget is exhausted.
    """
    schema_dict = output_schema.model_json_schema()

    force_message = {
        "role": "user",
        "content": (
            "⚠️ STEP LIMIT REACHED. You MUST now produce your final output immediately.\n\n"
            "Synthesise everything you have gathered so far and call submit_output.\n"
            "Even if your analysis is incomplete, submit what you have. "
            "Mark any incomplete areas in your output.\n\n"
            f"Required output schema:\n```json\n{json.dumps(schema_dict, indent=2)}\n```"
        ),
    }
    messages.append(force_message)

    submit_tool = _build_submit_tool()

    try:
        response = llm.chat(
            messages=messages,
            tools=[submit_tool],
            tool_choice={"type": "function", "function": {"name": "submit_output"}},
            temperature=0.0,
            max_tokens=4096,
        )

        choice = response.choices[0]
        message = choice.message

        if message.tool_calls:
            for tc in message.tool_calls:
                if tc.function.name == "submit_output":
                    raw_args = tc.function.arguments
                    args = json.loads(raw_args) if isinstance(raw_args, str) else raw_args
                    output_data = args.get("output", args)
                    try:
                        result = output_schema(**output_data)
                        brain.write_journal(run_id, task_id, step + 1, "forced_output",
                                            output_data)
                        return result
                    except ValidationError:
                        pass

        # Last resort: try to extract from text content
        if message.content:
            result = _try_parse_output(message.content, output_schema, brain, run_id, task_id, step + 1)
            if result:
                return result

    except Exception as exc:
        logger.error("forced_output_llm_failed", error=str(exc))

    # Absolute last resort: construct minimal valid output
    logger.warning("forced_output_minimal", agent_type=brain.AGENT_TYPE)
    return _construct_minimal_output(output_schema, brain, run_id, task_id, step + 1)


def _try_parse_output(
    text: str,
    output_schema: Type[BaseModel],
    brain,
    run_id: str,
    task_id: str,
    step: int,
) -> Optional[BaseModel]:
    """Attempt to parse text content as the output schema."""
    # Try to find JSON in the text
    import re
    json_patterns = [
        re.compile(r'```json\s*\n(.*?)\n```', re.DOTALL),
        re.compile(r'```\s*\n(.*?)\n```', re.DOTALL),
        re.compile(r'\{.*\}', re.DOTALL),
    ]

    for pattern in json_patterns:
        match = pattern.search(text)
        if match:
            try:
                data = json.loads(match.group(1) if pattern.groups else match.group(0))
                result = output_schema(**data)
                brain.write_journal(run_id, task_id, step, "forced_output", data)
                return result
            except (json.JSONDecodeError, ValidationError):
                continue

    return None


def _construct_minimal_output(
    output_schema: Type[BaseModel],
    brain,
    run_id: str,
    task_id: str,
    step: int,
) -> BaseModel:
    """
    Construct a minimal valid instance of the output schema.
    Uses schema defaults and empty values for required fields.
    """
    schema = output_schema.model_json_schema()
    minimal: Dict[str, Any] = {}

    properties = schema.get("properties", {})
    required_fields = schema.get("required", [])

    for field_name, field_spec in properties.items():
        field_type = field_spec.get("type", "string")
        if "default" in field_spec:
            minimal[field_name] = field_spec["default"]
        elif field_name in required_fields:
            type_defaults = {
                "string": f"[incomplete — {brain.AGENT_TYPE} reached step limit]",
                "integer": 0,
                "number": 0.0,
                "boolean": False,
                "array": [],
                "object": {},
            }
            minimal[field_name] = type_defaults.get(field_type, "")

    try:
        result = output_schema(**minimal)
    except ValidationError:
        # If even minimal fails, try model_construct (no validation)
        result = output_schema.model_construct(**minimal)

    brain.write_journal(run_id, task_id, step, "forced_output",
                        {"minimal": True, "data": minimal})
    return result
