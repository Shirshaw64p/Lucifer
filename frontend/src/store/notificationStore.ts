import { create } from 'zustand'

export interface Notification {
  id: string
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical'
  title: string
  message: string
  timestamp: string
  read: boolean
}

interface NotificationState {
  notifications: Notification[]
  addNotification: (n: Omit<Notification, 'id' | 'read'>) => void
  markRead: (id: string) => void
  clearAll: () => void
  unreadCount: () => number
}

let notifId = 0

export const useNotificationStore = create<NotificationState>((set, get) => ({
  notifications: [],

  addNotification: (n) =>
    set((state) => ({
      notifications: [
        { ...n, id: String(++notifId), read: false },
        ...state.notifications.slice(0, 99),
      ],
    })),

  markRead: (id) =>
    set((state) => ({
      notifications: state.notifications.map((n) =>
        n.id === id ? { ...n, read: true } : n,
      ),
    })),

  clearAll: () => set({ notifications: [] }),

  unreadCount: () => get().notifications.filter((n) => !n.read).length,
}))
