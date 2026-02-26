# Agent 2 — Completion Manifest

**Status:** ✅ COMPLETE  
**Scope:** Agent Brain Framework & Orchestrator  
**Total Files Created/Updated:** 17

---

## Framework Core (6 files)

| File | Purpose |
|------|---------|
| `agents/__init__.py` | Package init — re-exports registry, llm, base |
| `agents/brains/__init__.py` | Brain package — imports all 10 brain classes |
| `agents/llm.py` | LiteLLM abstraction — model registry, fallback chain (Sonnet→GPT-4o→Ollama), token tracking, sync/async, structlog |
| `agents/base.py` | `AgentBrain` ABC — journal (SQLite), memory (ChromaDB), run lifecycle, pre/post hooks, Pydantic schema enforcement |
| `agents/react.py` | ReAct loop engine — Thought→Action→Observation cycle, scope guard integration, approval gate with DB persistence, token budget enforcement |
| `agents/orchestrator.py` | LangGraph stateful graph — PLAN→DELEGATE→WAIT_FOR_REPORT→APPROVAL_GATE→ANALYZE→COMPLETE, Celery dispatch, PostgreSQL state persistence (SQLite fallback), crash recovery |
| `agents/registry.py` | Agent type→brain class mapping — lazy population, dynamic registration |

## Brain Files (10 files)

| File | Brain Class | Model | Steps | Token Budget | Tools | Approval Required |
|------|-------------|-------|-------|-------------|-------|-------------------|
| `agents/brains/recon.py` | `ReconBrain` | claude-3-5-haiku | 50 | 100K | 8 | None |
| `agents/brains/web.py` | `WebBrain` | claude-3-5-sonnet | 80 | 200K | 10 | ssrf_test |
| `agents/brains/injection.py` | `InjectionBrain` | claude-3-5-sonnet | 100 | 250K | 9 | All 7 injection tests |
| `agents/brains/auth.py` | `AuthBrain` | claude-3-5-sonnet | 80 | 200K | 8 | bruteforce, privesc, mfa_bypass |
| `agents/brains/api.py` | `APIBrain` | claude-3-5-sonnet | 90 | 225K | 8 | bola, bfla, mass_assignment |
| `agents/brains/cloud.py` | `CloudBrain` | claude-3-5-sonnet | 60 | 150K | 9 | metadata, kubernetes |
| `agents/brains/network.py` | `NetworkBrain` | claude-3-5-haiku | 40 | 80K | 7 | snmp_check |
| `agents/brains/evidence.py` | `EvidenceBrain` | claude-3-5-sonnet | 30 | 75K | 7 | None |
| `agents/brains/knowledge.py` | `KnowledgeBrain` | claude-3-5-haiku | 1 (single-pass) | 30K | 5 | None |
| `agents/brains/report.py` | `ReportBrain` | claude-3-5-sonnet | 1 (single-pass) | 50K | 5 | None |

## Architecture Summary

### LLM Layer (`agents/llm.py`)
- **Provider:** LiteLLM (unified interface to Anthropic, OpenAI, Ollama)
- **Fallback Chain:** claude-3-5-sonnet → gpt-4o → ollama/llama3.1:70b
- **Retryable Errors:** RateLimitError, ServiceUnavailableError, APIConnectionError, Timeout
- **Tracking:** Per-call and cumulative token counts, cost estimation via `litellm.completion_cost`

### Agent Base (`agents/base.py`)
- Abstract fields: AGENT_TYPE, LLM_MODEL, SYSTEM_PROMPT, MAX_STEPS, TOKEN_BUDGET, APPROVAL_REQUIRED_TOOLS
- Abstract methods: `get_tools()`, `get_input_schema()`, `get_output_schema()`
- Journal persistence: SQLite at `data/journals.sqlite3`
- Agent memory: ChromaDB per-agent namespace at `data/chromadb/`
- Hooks: `pre_run_hook()` / `post_run_hook()` for subclass customization

### ReAct Engine (`agents/react.py`)
- Loop: System prompt → [Thought → Action → Observation]* → Submit output
- Scope guard: Every tool call validated against run scope before execution
- Approval gate: Dangerous tools blocked until human approval (DB-persisted, poll-based)
- Budget enforcement: Token tracking checked every iteration
- Graceful degradation: `_force_output()` if MAX_STEPS exhausted, `_construct_minimal_output()` as last resort

### Orchestrator (`agents/orchestrator.py`)
- **Graph:** LangGraph StateGraph with conditional edges
- **Nodes:** PLAN, DELEGATE, WAIT_FOR_REPORT, APPROVAL_GATE, ANALYZE, COMPLETE
- **Dispatch:** Celery tasks (synchronous fallback for dev)
- **Persistence:** PostgreSQL preferred, SQLite fallback — state saved after every node transition
- **Crash Recovery:** Resumes from last persisted state on restart
- **Timeouts:** 2h per agent wait, 1h approval gate

### Registry (`agents/registry.py`)
- Maps agent_type strings to AgentBrain subclasses
- Lazy population from `agents/brains/` package
- Public API: `get_brain_class()`, `register_brain()`, `list_agents()`

## Dependencies Required

```
litellm>=1.40
langgraph>=0.2
pydantic>=2.0
chromadb>=0.4
celery>=5.3
structlog>=23.0
psycopg2-binary>=2.9  # or asyncpg
```

## Confirmation

All **10 brain files** are complete with:
- ✅ Full Pydantic input/output schemas
- ✅ Tool definitions with parameter schemas
- ✅ Approval-required tool lists where appropriate
- ✅ Custom system prompts tailored to each agent's domain
- ✅ Tuned MAX_STEPS and TOKEN_BUDGET per agent complexity
- ✅ Single-pass overrides for knowledge and report brains
