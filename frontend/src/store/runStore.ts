import { create } from 'zustand'
import type { WSAgentStatus } from '../lib/api'

interface RunState {
  activeRunId: string | null
  runStatus: string | null
  agentStatuses: Map<string, WSAgentStatus>
  liveFindingsCount: number

  setActiveRun: (runId: string | null) => void
  setRunStatus: (status: string) => void
  updateAgentStatus: (status: WSAgentStatus) => void
  incrementFindings: () => void
  resetFindings: () => void
  reset: () => void
}

export const useRunStore = create<RunState>((set) => ({
  activeRunId: null,
  runStatus: null,
  agentStatuses: new Map(),
  liveFindingsCount: 0,

  setActiveRun: (runId) => set({ activeRunId: runId }),
  setRunStatus: (status) => set({ runStatus: status }),

  updateAgentStatus: (status) =>
    set((state) => {
      const next = new Map(state.agentStatuses)
      next.set(status.agent_id, status)
      return { agentStatuses: next }
    }),

  incrementFindings: () =>
    set((state) => ({ liveFindingsCount: state.liveFindingsCount + 1 })),

  resetFindings: () => set({ liveFindingsCount: 0 }),

  reset: () =>
    set({
      activeRunId: null,
      runStatus: null,
      agentStatuses: new Map(),
      liveFindingsCount: 0,
    }),
}))
