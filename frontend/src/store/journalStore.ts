import { create } from 'zustand'
import type { WSJournalEntry } from '../lib/api'

const MAX_ENTRIES = 500

interface JournalState {
  entries: WSJournalEntry[]
  addEntry: (entry: WSJournalEntry) => void
  clear: () => void
}

export const useJournalStore = create<JournalState>((set) => ({
  entries: [],

  addEntry: (entry) =>
    set((state) => {
      const next = [entry, ...state.entries]
      if (next.length > MAX_ENTRIES) {
        next.length = MAX_ENTRIES // drop oldest
      }
      return { entries: next }
    }),

  clear: () => set({ entries: [] }),
}))
