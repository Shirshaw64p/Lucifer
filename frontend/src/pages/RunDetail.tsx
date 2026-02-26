import { useEffect, useState, useRef, useCallback } from 'react'
import { useParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import {
  Bot,
  Brain,
  ChevronDown,
  ChevronUp,
  Clock,
  Filter,
  ShieldAlert,
  ShieldCheck,
  Zap,
} from 'lucide-react'
import {
  runsApi,
  findingsApi,
  approvalsApi,
  LuciferWebSocket,
  type RunDetail as RunDetailType,
  type Finding,
  type ApprovalEvent,
  type WSJournalEntry,
  type WSAgentStatus,
  type WSFindingEvent,
  type WSApprovalRequest,
} from '../lib/api'
import { useRunStore } from '../store/runStore'
import { useJournalStore } from '../store/journalStore'
import { useApprovalStore } from '../store/approvalStore'
import { useNotificationStore } from '../store/notificationStore'

const severityColors: Record<string, string> = {
  critical: 'bg-red-500 text-white',
  high: 'bg-orange-500 text-white',
  medium: 'bg-yellow-500 text-black',
  low: 'bg-blue-500 text-white',
  info: 'bg-gray-500 text-white',
}

const statusColors: Record<string, string> = {
  idle: 'text-gray-400',
  running: 'text-green-400',
  complete: 'text-blue-400',
  error: 'text-red-400',
}

const entryTypeColors: Record<string, string> = {
  thought: 'border-l-purple-500',
  action: 'border-l-blue-500',
  observation: 'border-l-green-500',
  error: 'border-l-red-500',
}

export default function RunDetail() {
  const { runId } = useParams<{ runId: string }>()
  const { updateAgentStatus, incrementFindings } = useRunStore()
  const { entries: journalEntries, addEntry } = useJournalStore()
  const { pending: pendingApprovals, addRequest, removeRequest } = useApprovalStore()
  const { addNotification } = useNotificationStore()
  const [liveFindings, setLiveFindings] = useState<WSFindingEvent[]>([])
  const [agentStatuses, setAgentStatuses] = useState<WSAgentStatus[]>([])
  const [journalFilter, setJournalFilter] = useState<string>('')
  const [typeFilter, setTypeFilter] = useState<string>('')
  const [expandedEntries, setExpandedEntries] = useState<Set<number>>(new Set())
  const [approvalNotes, setApprovalNotes] = useState<string>('')
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null)

  const journalRef = useRef<HTMLDivElement>(null)

  const { data: run } = useQuery({
    queryKey: ['run', runId],
    queryFn: () => runsApi.get(runId!),
    enabled: !!runId,
    refetchInterval: 5000,
  })

  const { data: findings = [] } = useQuery({
    queryKey: ['findings', runId],
    queryFn: () => findingsApi.list(runId!),
    enabled: !!runId,
    refetchInterval: 5000,
  })

  const { data: approvals = [] } = useQuery({
    queryKey: ['approvals', runId],
    queryFn: () => approvalsApi.list(runId),
    enabled: !!runId,
    refetchInterval: 5000,
  })

  // WebSocket connections
  useEffect(() => {
    if (!runId) return

    const journalWs = new LuciferWebSocket(runId, 'journal')
    const findingsWs = new LuciferWebSocket(runId, 'findings')
    const approvalsWs = new LuciferWebSocket(runId, 'approvals')
    const statusWs = new LuciferWebSocket(runId, 'agent-status')

    journalWs.on('journal', (data) => {
      addEntry(data as WSJournalEntry)
    })

    findingsWs.on('finding', (data) => {
      const f = data as WSFindingEvent
      setLiveFindings((prev) => [f, ...prev.slice(0, 99)])
      incrementFindings()
      addNotification({
        severity: f.severity as 'info' | 'low' | 'medium' | 'high' | 'critical',
        title: `New Finding: ${f.title}`,
        message: `Found by ${f.agent_name || 'unknown agent'}`,
        timestamp: f.timestamp,
      })
    })

    approvalsWs.on('approval', (data) => {
      addRequest(data as WSApprovalRequest)
    })

    statusWs.on('agent_status', (data) => {
      const s = data as WSAgentStatus
      setAgentStatuses((prev) => {
        const next = prev.filter((a) => a.agent_id !== s.agent_id)
        return [s, ...next]
      })
      updateAgentStatus(s)
    })

    journalWs.connect()
    findingsWs.connect()
    approvalsWs.connect()
    statusWs.connect()

    return () => {
      journalWs.disconnect()
      findingsWs.disconnect()
      approvalsWs.disconnect()
      statusWs.disconnect()
    }
  }, [runId, addEntry, incrementFindings, updateAgentStatus, addRequest, addNotification])

  const handleApprove = async (approvalId: string) => {
    if (!runId) return
    try {
      await runsApi.approve(runId, { status: 'approved', reviewer: 'operator', notes: approvalNotes })
      removeRequest(approvalId)
      setApprovalNotes('')
    } catch { /* silent */ }
  }

  const handleReject = async (approvalId: string) => {
    if (!runId) return
    try {
      await runsApi.approve(runId, { status: 'denied', reviewer: 'operator', notes: approvalNotes })
      removeRequest(approvalId)
      setApprovalNotes('')
    } catch { /* silent */ }
  }

  const filteredJournal = journalEntries.filter((e) => {
    if (journalFilter && !e.agent_name.toLowerCase().includes(journalFilter.toLowerCase())) return false
    if (typeFilter && e.entry_type !== typeFilter) return false
    return true
  })

  const toggleEntry = (idx: number) => {
    setExpandedEntries((prev) => {
      const next = new Set(prev)
      if (next.has(idx)) next.delete(idx)
      else next.add(idx)
      return next
    })
  }

  const pendingApprovalsList = approvals.filter((a: ApprovalEvent) => a.status === 'pending')

  return (
    <div className="p-8 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">{run?.name || 'Run Detail'}</h1>
          <p className="text-muted-foreground mt-1">
            Status:{' '}
            <span className={`font-semibold ${run?.status === 'running' ? 'text-green-400' : 'text-muted-foreground'}`}>
              {run?.status || 'loading...'}
            </span>
            {' · '}
            {run?.targets.length || 0} targets · {findings.length} findings
          </p>
        </div>
      </div>

      {/* Approval Panel (prominent when pending) */}
      {pendingApprovalsList.length > 0 && (
        <div className="bg-yellow-900/20 border-2 border-yellow-500 rounded-lg p-6">
          <div className="flex items-center gap-2 mb-4">
            <ShieldAlert className="h-6 w-6 text-yellow-500" />
            <h2 className="text-xl font-bold text-yellow-500">Approval Required</h2>
          </div>
          {pendingApprovalsList.map((a: ApprovalEvent) => (
            <div key={a.id} className="bg-card border border-border rounded-lg p-4 mb-3">
              <div className="flex items-center justify-between mb-2">
                <span className="font-medium">Action: {a.action_type}</span>
                <span className="px-2 py-0.5 rounded-full text-xs font-medium bg-red-500/20 text-red-400 border border-red-500/30">
                  High Risk
                </span>
              </div>
              <p className="text-sm text-muted-foreground mb-3">
                {JSON.stringify(a.action_detail)}
              </p>
              <textarea
                value={approvalNotes}
                onChange={(e) => setApprovalNotes(e.target.value)}
                placeholder="Add notes (optional)..."
                className="w-full bg-background border border-border rounded-md px-3 py-2 text-sm mb-3"
                rows={2}
              />
              <div className="flex gap-2">
                <button
                  onClick={() => handleApprove(a.id)}
                  className="flex items-center gap-2 px-4 py-2 bg-green-600 text-white rounded-md hover:bg-green-700 transition-colors"
                >
                  <ShieldCheck className="h-4 w-4" />
                  Approve
                </button>
                <button
                  onClick={() => handleReject(a.id)}
                  className="flex items-center gap-2 px-4 py-2 bg-red-600 text-white rounded-md hover:bg-red-700 transition-colors"
                >
                  <ShieldAlert className="h-4 w-4" />
                  Reject
                </button>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Agent Status Panel */}
      <div className="bg-card border border-border rounded-lg p-6">
        <h2 className="text-lg font-semibold mb-4 flex items-center gap-2">
          <Brain className="h-5 w-5" />
          Agent Status
        </h2>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {agentStatuses.length === 0 ? (
            <p className="text-muted-foreground col-span-full">
              No agent status updates yet. Start the run to see agent activity.
            </p>
          ) : (
            agentStatuses.map((agent) => (
              <div key={agent.agent_id} className="bg-background border border-border rounded-lg p-4">
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-2">
                    <Bot className="h-4 w-4" />
                    <span className="font-medium">{agent.agent_name}</span>
                  </div>
                  <span className={`text-sm font-medium ${statusColors[agent.status] || 'text-gray-400'}`}>
                    {agent.status}
                  </span>
                </div>
                <p className="text-xs text-muted-foreground mb-2">
                  Model: {agent.llm_model}
                </p>
                {agent.current_step && (
                  <p className="text-xs text-muted-foreground mb-2 flex items-center gap-1">
                    <Zap className="h-3 w-3" />
                    Step: {agent.current_step}
                  </p>
                )}
                {/* Token budget progress bar */}
                <div className="mt-2">
                  <div className="flex justify-between text-xs text-muted-foreground mb-1">
                    <span>Tokens</span>
                    <span>
                      {agent.tokens_used.toLocaleString()} / {agent.token_budget.toLocaleString()}
                    </span>
                  </div>
                  <div className="w-full bg-muted rounded-full h-2">
                    <div
                      className="bg-primary h-2 rounded-full transition-all"
                      style={{
                        width: `${Math.min((agent.tokens_used / Math.max(agent.token_budget, 1)) * 100, 100)}%`,
                      }}
                    />
                  </div>
                </div>
              </div>
            ))
          )}
        </div>
      </div>

      {/* Two-column layout: Journal + Findings */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Live Journal Stream */}
        <div className="bg-card border border-border rounded-lg">
          <div className="p-4 border-b border-border">
            <h2 className="text-lg font-semibold mb-3 flex items-center gap-2">
              <Clock className="h-5 w-5" />
              Live Journal
            </h2>
            <div className="flex gap-2">
              <input
                type="text"
                placeholder="Filter by agent..."
                value={journalFilter}
                onChange={(e) => setJournalFilter(e.target.value)}
                className="flex-1 bg-background border border-border rounded-md px-3 py-1.5 text-sm"
              />
              <select
                value={typeFilter}
                onChange={(e) => setTypeFilter(e.target.value)}
                className="bg-background border border-border rounded-md px-3 py-1.5 text-sm"
              >
                <option value="">All types</option>
                <option value="thought">Thought</option>
                <option value="action">Action</option>
                <option value="observation">Observation</option>
                <option value="error">Error</option>
              </select>
            </div>
          </div>
          <div ref={journalRef} className="max-h-[500px] overflow-y-auto">
            {filteredJournal.length === 0 ? (
              <p className="p-6 text-center text-muted-foreground">
                No journal entries yet. They will appear here in real-time.
              </p>
            ) : (
              filteredJournal.map((entry, idx) => (
                <div
                  key={idx}
                  className={`border-l-4 ${entryTypeColors[entry.entry_type] || 'border-l-gray-500'} p-3 border-b border-border cursor-pointer hover:bg-muted/30`}
                  onClick={() => toggleEntry(idx)}
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-medium text-primary">{entry.agent_name}</span>
                      <span className="text-xs px-1.5 py-0.5 rounded bg-muted text-muted-foreground">
                        {entry.entry_type}
                      </span>
                    </div>
                    <div className="flex items-center gap-1">
                      <span className="text-xs text-muted-foreground">
                        {new Date(entry.timestamp).toLocaleTimeString()}
                      </span>
                      {expandedEntries.has(idx) ? (
                        <ChevronUp className="h-3 w-3" />
                      ) : (
                        <ChevronDown className="h-3 w-3" />
                      )}
                    </div>
                  </div>
                  <p className="text-sm mt-1 text-muted-foreground truncate">
                    {entry.content}
                  </p>
                  {expandedEntries.has(idx) && (
                    <div className="mt-2 p-2 bg-background rounded text-xs font-mono whitespace-pre-wrap">
                      {entry.content}
                      {entry.metadata && (
                        <pre className="mt-2 text-muted-foreground">
                          {JSON.stringify(entry.metadata, null, 2)}
                        </pre>
                      )}
                    </div>
                  )}
                </div>
              ))
            )}
          </div>
        </div>

        {/* Findings Panel */}
        <div className="bg-card border border-border rounded-lg">
          <div className="p-4 border-b border-border">
            <h2 className="text-lg font-semibold flex items-center gap-2">
              <ShieldAlert className="h-5 w-5" />
              Findings ({findings.length})
            </h2>
          </div>
          <div className="max-h-[500px] overflow-y-auto divide-y divide-border">
            {findings.length === 0 && liveFindings.length === 0 ? (
              <p className="p-6 text-center text-muted-foreground">
                No findings yet.
              </p>
            ) : (
              <>
                {/* Live findings from WS */}
                {liveFindings.map((f, idx) => (
                  <div
                    key={`live-${idx}`}
                    className="p-3 hover:bg-muted/30 transition-colors cursor-pointer"
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-medium text-sm">{f.title}</span>
                      <span
                        className={`px-2 py-0.5 rounded-full text-xs font-medium ${
                          severityColors[f.severity] || 'bg-gray-500 text-white'
                        }`}
                      >
                        {f.severity}
                      </span>
                    </div>
                    <p className="text-xs text-muted-foreground mt-1">
                      {f.agent_name || 'Unknown agent'} · {new Date(f.timestamp).toLocaleTimeString()}
                    </p>
                  </div>
                ))}
                {/* DB findings */}
                {findings.map((f: Finding) => (
                  <div
                    key={f.id}
                    className="p-3 hover:bg-muted/30 transition-colors cursor-pointer"
                    onClick={() => setSelectedFinding(f)}
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-medium text-sm">{f.title}</span>
                      <span
                        className={`px-2 py-0.5 rounded-full text-xs font-medium ${
                          severityColors[f.severity] || 'bg-gray-500 text-white'
                        }`}
                      >
                        {f.severity}
                      </span>
                    </div>
                    <p className="text-xs text-muted-foreground mt-1">
                      {new Date(f.created_at).toLocaleString()}
                    </p>
                  </div>
                ))}
              </>
            )}
          </div>
        </div>
      </div>

      {/* Finding Detail Modal */}
      {selectedFinding && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-8">
          <div className="bg-card border border-border rounded-lg max-w-2xl w-full max-h-[80vh] overflow-y-auto p-6">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-xl font-bold">{selectedFinding.title}</h2>
              <button
                onClick={() => setSelectedFinding(null)}
                className="text-muted-foreground hover:text-foreground"
              >
                ✕
              </button>
            </div>
            <div className="flex gap-2 mb-4">
              <span
                className={`px-2.5 py-0.5 rounded-full text-xs font-medium ${
                  severityColors[selectedFinding.severity]
                }`}
              >
                {selectedFinding.severity}
              </span>
              {selectedFinding.cvss_score != null && (
                <span className="px-2.5 py-0.5 rounded-full text-xs font-medium bg-muted">
                  CVSS: {selectedFinding.cvss_score}
                </span>
              )}
            </div>
            <div className="space-y-4 text-sm">
              <div>
                <h3 className="font-semibold text-muted-foreground mb-1">Description</h3>
                <p className="whitespace-pre-wrap">{selectedFinding.description}</p>
              </div>
              {selectedFinding.remediation && (
                <div>
                  <h3 className="font-semibold text-muted-foreground mb-1">Remediation</h3>
                  <p className="whitespace-pre-wrap">{selectedFinding.remediation}</p>
                </div>
              )}
              {selectedFinding.raw_output && (
                <div>
                  <h3 className="font-semibold text-muted-foreground mb-1">Raw Output</h3>
                  <pre className="bg-background p-3 rounded text-xs overflow-x-auto">
                    {selectedFinding.raw_output}
                  </pre>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
