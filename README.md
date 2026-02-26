# Lucifer — Autonomous AI Red-Team Platform

> **An AI-driven offensive-security platform that autonomously plans, executes, and reports red-team engagements.**

Lucifer orchestrates a swarm of specialised AI agents — Recon, Exploit, Lateral-Move, Persist, Clean-up, and Report — through an agentic loop with human-in-the-loop approval gates. Every action is scope-guarded, evidence-stored, and streamed to a live React dashboard.

---

## Architecture

| Layer | Technology |
|-------|-----------|
| Frontend | React 18, TypeScript, Vite, Tailwind CSS, Zustand, TanStack Query, Recharts |
| Backend API | Python 3.12, FastAPI, SQLAlchemy 2.x (async), Pydantic v2 |
| Task Queue | Celery 5 + Redis |
| Database | PostgreSQL 16 |
| Vector Store | ChromaDB |
| Object Storage | MinIO |
| OAST Callbacks | Interactsh |
| LLM Layer | LiteLLM (OpenAI, Anthropic, local models) |

---

## Prerequisites

- **Docker & Docker Compose** (v2)
- **Node.js ≥ 18** (for frontend build)
- **Python 3.12+** (for backend / tools development)
- An API key for at least one LLM provider (OpenAI, Anthropic, etc.)

---

## Quick Start

### 1. Clone & configure

```bash
git clone <repo-url> && cd Lucifer
cp .env.example .env
# Edit .env — set LLM_API_KEY and any other overrides
```

### 2. Start infrastructure

```bash
docker compose up -d
```

This starts PostgreSQL, Redis, ChromaDB, MinIO, and Interactsh.

### 3. Run database migrations

```bash
cd backend
alembic upgrade head
```

### 4. Start the backend

```bash
# API server
uvicorn app.main:app --host 0.0.0.0 --port 8080 --reload

# Celery worker (in a separate terminal)
celery -A app.tasks.celery_app worker -l info
```

### 5. Start the frontend

```bash
cd frontend
npm install
npm run dev
```

Open **http://localhost:5173** — login with `admin` / `admin`.

### 6. Run the E2E smoke test

```bash
pip install pytest requests websockets
pytest tests/test_e2e.py -v --timeout=120
```

---

## Project Structure

```
├── backend/                 # FastAPI application
│   ├── app/
│   │   ├── api/v1/         # REST endpoints (auth, runs, targets, findings, …)
│   │   ├── core/           # Config, DB, security, logging
│   │   ├── models/         # SQLAlchemy ORM models
│   │   ├── schemas/        # Pydantic request/response schemas
│   │   └── tasks/          # Celery tasks
│   ├── websocket_manager.py
│   ├── run_coordinator.py  # Orchestration Celery task
│   └── alembic/            # Database migrations
├── frontend/               # React + Vite dashboard
│   └── src/
│       ├── lib/            # API client, utilities
│       ├── store/          # Zustand state stores
│       └── pages/          # Dashboard, RunDetail, Findings, KB, NewRun, Reports
├── agents/                 # LLM abstraction & agent brains
├── core/                   # Shared models, scope guard, config
├── tools/                  # Evidence store, tool integrations
├── reports/                # Report generation models
├── tests/                  # E2E smoke tests
└── docker-compose.yml      # Infrastructure services
```

---

## Key Pages

| Page | Description |
|------|-------------|
| **Dashboard** | Summary cards, sparkline chart, recent runs table |
| **New Run** | Configure engagement — targets, mode, scope, objective |
| **Run Detail** | Live agent status, journal stream, findings, approval gates |
| **Findings** | Filterable/sortable vulnerability table with detail modals |
| **Knowledge Base** | Upload CVEs, playbooks; drag-and-drop; search with relevance scoring |
| **Reports** | Download JSON reports for completed engagements |

---

## WebSocket Channels

Each run exposes four real-time WebSocket channels:

| Channel | Path | Payload |
|---------|------|---------|
| Journal | `/ws/runs/{id}/journal` | Agent thoughts, actions, observations |
| Findings | `/ws/runs/{id}/findings` | New vulnerability discoveries |
| Approvals | `/ws/runs/{id}/approvals` | Human-approval requests |
| Agent Status | `/ws/runs/{id}/agent-status` | Agent state changes, token usage |

---

## Environment Variables

See `.env.example` for the full list. Key variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | `postgresql+asyncpg://lucifer:lucifer@localhost:5432/lucifer` | PostgreSQL connection |
| `REDIS_URL` | `redis://localhost:6379/0` | Redis for Celery + caching |
| `JWT_SECRET_KEY` | (generate one) | JWT signing key |
| `LLM_DEFAULT_PROVIDER` | `openai` | Default LLM provider |
| `LLM_API_KEY` | — | API key for LLM provider |
| `MINIO_ENDPOINT` | `localhost:9000` | MinIO endpoint |
| `CHROMA_HOST` | `localhost` | ChromaDB host |

---

## License

Licensed under the **Business Source License 1.1** (BSL 1.1).

- **Change Date:** February 25, 2030
- **Change License:** Apache License 2.0
- **Additional Use Grant:** Usage is permitted for lawful, authorised security testing only.

See [LICENSE](LICENSE) for the full text.