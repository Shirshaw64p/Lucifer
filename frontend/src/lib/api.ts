/**
 * Typed API client for the Lucifer backend.
 *
 * - Axios instance with base URL from env and JWT interceptor
 * - Typed functions for every endpoint in the spec
 * - WebSocket client class with reconnect logic
 */

import axios, { type AxiosInstance } from 'axios'

// ═══════════════════════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════════════════════

export interface TokenPair {
  access_token: string
  refresh_token: string
  token_type: string
}

export interface Run {
  id: string
  name: string
  status: string
  config: Record<string, unknown> | null
  owner_id: string | null
  created_at: string
  updated_at: string
}

export interface RunDetail extends Run {
  targets: Target[]
  findings_count: number
  agents_count: number
}

export interface Target {
  id: string
  run_id: string
  target_type: string
  value: string
  in_scope: boolean
  metadata?: Record<string, unknown> | null
  created_at: string
}

export interface Finding {
  id: string
  run_id: string
  target_id: string | null
  title: string
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical'
  cvss_score: number | null
  description: string
  remediation: string | null
  raw_output: string | null
  agent_id: string | null
  created_at: string
}

export interface FindingDetail extends Finding {
  evidence_artifacts: EvidenceArtifact[]
  agent_name: string | null
  target_value: string | null
}

export interface EvidenceArtifact {
  id: string
  finding_id: string
  artifact_type: string
  storage_path: string
  mime_type: string
  size_bytes: number
  created_at: string
}

export interface ApprovalEvent {
  id: string
  run_id: string
  agent_id: string | null
  action_type: string
  action_detail: Record<string, unknown> | null
  status: 'pending' | 'approved' | 'denied'
  reviewer: string | null
  reviewed_at: string | null
  created_at: string
}

export interface Agent {
  id: string
  name: string
  agent_type: string
  description: string | null
  enabled: boolean
  config: Record<string, unknown> | null
  created_at: string
}

export interface KBDocument {
  id: string
  title: string
  doc_type: string
  content: string
  embedding_id: string | null
  metadata?: Record<string, unknown> | null
  created_at: string
  updated_at: string
}

export interface KBSearchResult {
  doc_id: string
  title: string
  chunk: string
  score: number
}

// ── WebSocket message types ─────────────────────────────────────────────

export interface WSJournalEntry {
  run_id: string
  agent_name: string
  entry_type: 'thought' | 'action' | 'observation' | 'error'
  content: string
  timestamp: string
  metadata?: Record<string, unknown>
}

export interface WSAgentStatus {
  run_id: string
  agent_id: string
  agent_name: string
  llm_model: string
  status: 'idle' | 'running' | 'complete' | 'error'
  current_step: string | null
  tokens_used: number
  token_budget: number
}

export interface WSFindingEvent {
  run_id: string
  finding_id: string
  title: string
  severity: string
  agent_name: string | null
  timestamp: string
}

export interface WSApprovalRequest {
  run_id: string
  approval_id: string
  agent_name: string | null
  action_type: string
  action_detail: Record<string, unknown> | null
  risk_level: string
  timestamp: string
}

// ═══════════════════════════════════════════════════════════════════════════
// Axios Instance
// ═══════════════════════════════════════════════════════════════════════════

const API_BASE = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8080'

const api: AxiosInstance = axios.create({
  baseURL: `${API_BASE}/api/v1`,
  headers: { 'Content-Type': 'application/json' },
  timeout: 30_000,
})

// JWT interceptor
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('lucifer_access_token')
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

api.interceptors.response.use(
  (r) => r,
  async (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem('lucifer_access_token')
    }
    return Promise.reject(error)
  },
)

// ═══════════════════════════════════════════════════════════════════════════
// Auth
// ═══════════════════════════════════════════════════════════════════════════

export const authApi = {
  login: async (username: string, password: string): Promise<TokenPair> => {
    const { data } = await api.post<TokenPair>('/auth/login', { username, password })
    localStorage.setItem('lucifer_access_token', data.access_token)
    localStorage.setItem('lucifer_refresh_token', data.refresh_token)
    return data
  },
  refresh: async (): Promise<TokenPair> => {
    const rt = localStorage.getItem('lucifer_refresh_token')
    const { data } = await api.post<TokenPair>('/auth/refresh', { refresh_token: rt })
    localStorage.setItem('lucifer_access_token', data.access_token)
    return data
  },
}

// ═══════════════════════════════════════════════════════════════════════════
// Runs
// ═══════════════════════════════════════════════════════════════════════════

export const runsApi = {
  list: async (): Promise<Run[]> => {
    const { data } = await api.get<Run[]>('/runs')
    return data
  },
  create: async (body: {
    name: string
    config?: Record<string, unknown>
    targets?: { target_type: string; value: string; in_scope?: boolean }[]
  }): Promise<RunDetail> => {
    const { data } = await api.post<RunDetail>('/runs', body)
    return data
  },
  get: async (id: string): Promise<RunDetail> => {
    const { data } = await api.get<RunDetail>(`/runs/${id}`)
    return data
  },
  update: async (id: string, body: Partial<Run>): Promise<Run> => {
    const { data } = await api.patch<Run>(`/runs/${id}`, body)
    return data
  },
  delete: async (id: string): Promise<void> => {
    await api.delete(`/runs/${id}`)
  },
  start: async (id: string): Promise<Run> => {
    const { data } = await api.post<Run>(`/runs/${id}/start`)
    return data
  },
  pause: async (id: string): Promise<Run> => {
    const { data } = await api.post<Run>(`/runs/${id}/pause`)
    return data
  },
  cancel: async (id: string): Promise<Run> => {
    const { data } = await api.post<Run>(`/runs/${id}/cancel`)
    return data
  },
  approve: async (id: string, decision: { status: string; reviewer?: string; notes?: string }): Promise<unknown> => {
    const { data } = await api.post(`/runs/${id}/approve`, decision)
    return data
  },
}

// ═══════════════════════════════════════════════════════════════════════════
// Targets
// ═══════════════════════════════════════════════════════════════════════════

export const targetsApi = {
  list: async (runId: string): Promise<Target[]> => {
    const { data } = await api.get<Target[]>(`/runs/${runId}/targets`)
    return data
  },
  create: async (runId: string, body: { target_type: string; value: string; in_scope?: boolean }): Promise<Target> => {
    const { data } = await api.post<Target>(`/runs/${runId}/targets`, body)
    return data
  },
  delete: async (runId: string, targetId: string): Promise<void> => {
    await api.delete(`/runs/${runId}/targets/${targetId}`)
  },
}

// ═══════════════════════════════════════════════════════════════════════════
// Findings
// ═══════════════════════════════════════════════════════════════════════════

export const findingsApi = {
  list: async (runId: string, severity?: string): Promise<Finding[]> => {
    const params = severity ? { severity } : {}
    const { data } = await api.get<Finding[]>(`/runs/${runId}/findings`, { params })
    return data
  },
  get: async (id: string): Promise<FindingDetail> => {
    const { data } = await api.get<FindingDetail>(`/findings/${id}`)
    return data
  },
  update: async (id: string, body: Partial<Finding>): Promise<Finding> => {
    const { data } = await api.patch<Finding>(`/findings/${id}`, body)
    return data
  },
}

// ═══════════════════════════════════════════════════════════════════════════
// Evidence
// ═══════════════════════════════════════════════════════════════════════════

export const evidenceApi = {
  list: async (findingId: string): Promise<EvidenceArtifact[]> => {
    const { data } = await api.get<EvidenceArtifact[]>(`/findings/${findingId}/evidence`)
    return data
  },
  upload: async (findingId: string, file: File, artifactType = 'other'): Promise<EvidenceArtifact> => {
    const form = new FormData()
    form.append('file', file)
    const { data } = await api.post<EvidenceArtifact>(
      `/findings/${findingId}/evidence?artifact_type=${artifactType}`,
      form,
      { headers: { 'Content-Type': 'multipart/form-data' } },
    )
    return data
  },
  download: async (evidenceId: string): Promise<void> => {
    window.open(`${API_BASE}/api/v1/evidence/${evidenceId}/download`, '_blank')
  },
}

// ═══════════════════════════════════════════════════════════════════════════
// Approvals
// ═══════════════════════════════════════════════════════════════════════════

export const approvalsApi = {
  list: async (runId?: string): Promise<ApprovalEvent[]> => {
    const params = runId ? { run_id: runId } : {}
    const { data } = await api.get<ApprovalEvent[]>('/approvals', { params })
    return data
  },
  decide: async (id: string, decision: { status: string; reviewer?: string }): Promise<ApprovalEvent> => {
    const { data } = await api.patch<ApprovalEvent>(`/approvals/${id}`, decision)
    return data
  },
}

// ═══════════════════════════════════════════════════════════════════════════
// Agents
// ═══════════════════════════════════════════════════════════════════════════

export const agentsApi = {
  list: async (): Promise<Agent[]> => {
    const { data } = await api.get<Agent[]>('/agents')
    return data
  },
  get: async (id: string): Promise<Agent> => {
    const { data } = await api.get<Agent>(`/agents/${id}`)
    return data
  },
  create: async (body: Partial<Agent>): Promise<Agent> => {
    const { data } = await api.post<Agent>('/agents', body)
    return data
  },
  update: async (id: string, body: Partial<Agent>): Promise<Agent> => {
    const { data } = await api.patch<Agent>(`/agents/${id}`, body)
    return data
  },
}

// ═══════════════════════════════════════════════════════════════════════════
// Knowledge Base
// ═══════════════════════════════════════════════════════════════════════════

export const kbApi = {
  list: async (): Promise<KBDocument[]> => {
    const { data } = await api.get<KBDocument[]>('/kb')
    return data
  },
  get: async (id: string): Promise<KBDocument> => {
    const { data } = await api.get<KBDocument>(`/kb/${id}`)
    return data
  },
  create: async (body: { title: string; doc_type: string; content: string }): Promise<KBDocument> => {
    const { data } = await api.post<KBDocument>('/kb', body)
    return data
  },
  delete: async (id: string): Promise<void> => {
    await api.delete(`/kb/${id}`)
  },
  search: async (query: string, limit = 3): Promise<KBSearchResult[]> => {
    const { data } = await api.get<KBSearchResult[]>('/kb/search', { params: { query, limit } })
    return data
  },
}

// ═══════════════════════════════════════════════════════════════════════════
// Reports
// ═══════════════════════════════════════════════════════════════════════════

export const reportsApi = {
  download: (runId: string): void => {
    window.open(`${API_BASE}/api/v1/reports/${runId}`, '_blank')
  },
}

// ═══════════════════════════════════════════════════════════════════════════
// WebSocket Client
// ═══════════════════════════════════════════════════════════════════════════

type WSMessageHandler = (data: unknown) => void

export class LuciferWebSocket {
  private ws: WebSocket | null = null
  private url: string
  private handlers: Map<string, WSMessageHandler[]> = new Map()
  private reconnectAttempts = 0
  private maxReconnectAttempts = 10
  private reconnectDelay = 1000
  private shouldReconnect = true

  constructor(runId: string, channel: 'journal' | 'findings' | 'approvals' | 'agent-status') {
    const WS_BASE = import.meta.env.VITE_WS_BASE_URL || 'ws://localhost:8080'
    this.url = `${WS_BASE}/ws/runs/${runId}/${channel}`
  }

  connect(): void {
    try {
      this.ws = new WebSocket(this.url)

      this.ws.onopen = () => {
        this.reconnectAttempts = 0
        this.emit('connected', null)
      }

      this.ws.onmessage = (event) => {
        try {
          const msg = JSON.parse(event.data)
          this.emit(msg.type || 'message', msg.data || msg)
        } catch {
          this.emit('message', event.data)
        }
      }

      this.ws.onclose = () => {
        this.emit('disconnected', null)
        if (this.shouldReconnect && this.reconnectAttempts < this.maxReconnectAttempts) {
          this.reconnectAttempts++
          const delay = this.reconnectDelay * Math.pow(2, this.reconnectAttempts - 1)
          setTimeout(() => this.connect(), Math.min(delay, 30000))
        }
      }

      this.ws.onerror = () => {
        this.emit('error', null)
      }
    } catch {
      // Silent fail — never crash
    }
  }

  on(event: string, handler: WSMessageHandler): void {
    if (!this.handlers.has(event)) {
      this.handlers.set(event, [])
    }
    this.handlers.get(event)!.push(handler)
  }

  off(event: string, handler: WSMessageHandler): void {
    const handlers = this.handlers.get(event)
    if (handlers) {
      const idx = handlers.indexOf(handler)
      if (idx >= 0) handlers.splice(idx, 1)
    }
  }

  private emit(event: string, data: unknown): void {
    const handlers = this.handlers.get(event)
    if (handlers) {
      handlers.forEach((h) => {
        try { h(data) } catch { /* silent */ }
      })
    }
  }

  disconnect(): void {
    this.shouldReconnect = false
    this.ws?.close()
    this.ws = null
  }
}

export default api
