# Lucifer — Engineering Master Specification v2

## 1. Vision & Mission

**Lucifer** is an autonomous AI-powered red-team / penetration-testing platform.
It orchestrates multiple AI agents that plan, execute, and report on offensive
security engagements — from reconnaissance through exploitation — while keeping
a human operator in the approval loop for high-risk actions.

## 2. High-Level Architecture

```
┌─────────────────────────────────────────────────┐
│                   Frontend (React)               │
│  Dashboard · Run Control · Findings · Approvals  │
└────────────────────┬────────────────────────────┘
                     │  REST / WebSocket
┌────────────────────▼────────────────────────────┐
│              Backend  (FastAPI)                   │
│  Auth · Runs API · Findings API · Agents API     │
│  Celery task queue · Scope guard · Logging        │
└──┬──────────┬──────────┬──────────┬─────────────┘
   │          │          │          │
   ▼          ▼          ▼          ▼
 Postgres   Redis    ChromaDB    MinIO
 (state)   (broker)  (vectors)  (artifacts)
```

## 3. Core Entities (DB Models)

| Model             | Purpose                                          |
|--------------------|--------------------------------------------------|
| Run               | A single pentest engagement / campaign            |
| Target            | IP, CIDR, domain, or URL in scope for a Run       |
| Finding           | Vulnerability or issue discovered                 |
| EvidenceArtifact  | Screenshot, pcap, log, or file tied to a Finding  |
| ApprovalEvent     | Human approve / deny record for risky actions      |
| Agent             | Registered AI agent (recon, exploit, report, etc.) |
| AgentMemory       | Per-agent vector memory stored in ChromaDB         |
| KBDocument        | Knowledge-base document (CVEs, playbooks, etc.)   |

### 3.1 Run
- id: UUID PK
- name: str
- status: enum (pending, running, paused, completed, failed, cancelled)
- created_at, updated_at: datetime
- config: JSONB (model params, depth, flags)
- owner_id: UUID FK → users

### 3.2 Target
- id: UUID PK
- run_id: UUID FK → runs
- target_type: enum (ip, cidr, domain, url)
- value: str  (the actual IP/domain/URL)
- in_scope: bool (default True)
- metadata_: JSONB

### 3.3 Finding
- id: UUID PK
- run_id: UUID FK → runs
- target_id: UUID FK → targets (nullable)
- title: str
- severity: enum (info, low, medium, high, critical)
- cvss_score: float (nullable)
- description: text
- remediation: text (nullable)
- raw_output: text (nullable)
- agent_id: UUID FK → agents (nullable)
- created_at: datetime

### 3.4 EvidenceArtifact
- id: UUID PK
- finding_id: UUID FK → findings
- artifact_type: enum (screenshot, pcap, log, report, other)
- storage_path: str  (MinIO object key)
- mime_type: str
- size_bytes: int
- created_at: datetime

### 3.5 ApprovalEvent
- id: UUID PK
- run_id: UUID FK → runs
- agent_id: UUID FK → agents (nullable)
- action_type: str  (e.g. "exploit", "brute_force", "exfil")
- action_detail: JSONB
- status: enum (pending, approved, denied)
- reviewer: str (nullable)
- reviewed_at: datetime (nullable)
- created_at: datetime

### 3.6 Agent
- id: UUID PK
- name: str (unique)
- agent_type: str  (recon, exploit, report, orchestrator, etc.)
- description: text (nullable)
- enabled: bool (default True)
- config: JSONB
- created_at: datetime

### 3.7 AgentMemory
- id: UUID PK
- agent_id: UUID FK → agents
- run_id: UUID FK → runs (nullable)
- collection_name: str  (ChromaDB collection)
- content_hash: str
- created_at: datetime

### 3.8 KBDocument
- id: UUID PK
- title: str
- doc_type: enum (cve, playbook, technique, reference)
- content: text
- embedding_id: str (nullable, ChromaDB ref)
- metadata_: JSONB
- created_at, updated_at: datetime

## 4. API Endpoints

### Auth
- POST /api/v1/auth/login          → JWT token pair
- POST /api/v1/auth/refresh         → refresh access token
- POST /api/v1/auth/api-keys        → create API key
- DELETE /api/v1/auth/api-keys/{id} → revoke API key

### Runs
- GET    /api/v1/runs
- POST   /api/v1/runs
- GET    /api/v1/runs/{id}
- PATCH  /api/v1/runs/{id}
- DELETE /api/v1/runs/{id}
- POST   /api/v1/runs/{id}/start
- POST   /api/v1/runs/{id}/pause
- POST   /api/v1/runs/{id}/cancel

### Targets
- GET    /api/v1/runs/{run_id}/targets
- POST   /api/v1/runs/{run_id}/targets
- DELETE /api/v1/runs/{run_id}/targets/{id}

### Findings
- GET    /api/v1/runs/{run_id}/findings
- POST   /api/v1/runs/{run_id}/findings
- GET    /api/v1/findings/{id}
- PATCH  /api/v1/findings/{id}

### Evidence
- POST   /api/v1/findings/{finding_id}/evidence   (multipart upload)
- GET    /api/v1/findings/{finding_id}/evidence
- GET    /api/v1/evidence/{id}/download

### Approvals
- GET    /api/v1/runs/{run_id}/approvals
- POST   /api/v1/approvals                         (request approval)
- PATCH  /api/v1/approvals/{id}                     (approve / deny)

### Agents
- GET    /api/v1/agents
- POST   /api/v1/agents
- GET    /api/v1/agents/{id}
- PATCH  /api/v1/agents/{id}

### Knowledge Base
- GET    /api/v1/kb
- POST   /api/v1/kb
- GET    /api/v1/kb/{id}
- DELETE /api/v1/kb/{id}

## 5. Scope Enforcement

Every tool invocation MUST pass through `tools/scope_guard.py`.
The guard:
1. Resolves the target to an IP / CIDR / domain.
2. Checks the target is listed in the Run's approved Target list with `in_scope=True`.
3. Blocks and logs any out-of-scope attempt.
4. Raises `ScopeViolationError` on violation.

## 6. Infrastructure

| Service      | Image / Version        | Port  | Purpose               |
|-------------|------------------------|-------|------------------------|
| PostgreSQL  | postgres:16            | 5432  | Primary state store    |
| Redis       | redis:7                | 6379  | Celery broker + cache  |
| ChromaDB    | chromadb/chroma:latest | 8000  | Vector embeddings      |
| MinIO       | minio/minio:latest     | 9000  | Artifact / object store|
| Interactsh  | projectdiscovery/interactsh-server | 8001 | OOB callback server |

## 7. Tech Stack

- **Backend**: Python 3.12, FastAPI, SQLAlchemy 2.x (async), Alembic
- **Task Queue**: Celery 5.x + Redis broker
- **Auth**: JWT (python-jose) + API key header auth
- **Config**: pydantic-settings, .env file
- **Logging**: structlog (JSON)
- **Frontend**: React + TypeScript (future)
- **Agents**: LangChain / LangGraph based agents (future)

## 8. Security Rules

1. All secrets in `.env` — never hardcoded.
2. JWT tokens expire in 30 min; refresh tokens in 7 days.
3. API keys are hashed (SHA-256) before storage.
4. CORS restricted to configured origins.
5. Every agent action passes Scope Guard before execution.
6. High-risk actions require human ApprovalEvent before proceeding.
