import { create } from 'zustand'
import type { WSApprovalRequest } from '../lib/api'

interface ApprovalState {
  pending: WSApprovalRequest[]
  addRequest: (req: WSApprovalRequest) => void
  removeRequest: (approvalId: string) => void
  clear: () => void
}

export const useApprovalStore = create<ApprovalState>((set) => ({
  pending: [],

  addRequest: (req) =>
    set((state) => ({
      pending: [req, ...state.pending.filter((p) => p.approval_id !== req.approval_id)],
    })),

  removeRequest: (approvalId) =>
    set((state) => ({
      pending: state.pending.filter((p) => p.approval_id !== approvalId),
    })),

  clear: () => set({ pending: [] }),
}))
