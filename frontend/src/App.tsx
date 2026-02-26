import { Routes, Route, Link, useLocation } from 'react-router-dom'
import {
  LayoutDashboard,
  Play,
  Search,
  FileText,
  BookOpen,
  PlusCircle,
  Shield,
} from 'lucide-react'
import Dashboard from './pages/Dashboard'
import RunDetail from './pages/RunDetail'
import Findings from './pages/Findings'
import KnowledgeBase from './pages/KnowledgeBase'
import NewRun from './pages/NewRun'
import Reports from './pages/Reports'

const navItems = [
  { path: '/', label: 'Dashboard', icon: LayoutDashboard },
  { path: '/runs/new', label: 'New Run', icon: PlusCircle },
  { path: '/findings', label: 'Findings', icon: Search },
  { path: '/kb', label: 'Knowledge Base', icon: BookOpen },
  { path: '/reports', label: 'Reports', icon: FileText },
]

export default function App() {
  const location = useLocation()

  return (
    <div className="flex h-screen overflow-hidden">
      {/* Sidebar */}
      <aside className="w-64 bg-card border-r border-border flex flex-col">
        <div className="p-6 border-b border-border">
          <div className="flex items-center gap-3">
            <Shield className="h-8 w-8 text-red-500" />
            <div>
              <h1 className="text-xl font-bold text-foreground">Lucifer</h1>
              <p className="text-xs text-muted-foreground">AI Red-Team Platform</p>
            </div>
          </div>
        </div>
        <nav className="flex-1 p-4 space-y-1">
          {navItems.map(({ path, label, icon: Icon }) => {
            const isActive = location.pathname === path
            return (
              <Link
                key={path}
                to={path}
                className={`flex items-center gap-3 px-3 py-2 rounded-md text-sm transition-colors ${
                  isActive
                    ? 'bg-primary/10 text-primary'
                    : 'text-muted-foreground hover:text-foreground hover:bg-muted'
                }`}
              >
                <Icon className="h-4 w-4" />
                {label}
              </Link>
            )
          })}
        </nav>
        <div className="p-4 border-t border-border">
          <p className="text-xs text-muted-foreground">v0.1.0 · BSL 1.1</p>
        </div>
      </aside>

      {/* Main content */}
      <main className="flex-1 overflow-auto">
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/runs/new" element={<NewRun />} />
          <Route path="/runs/:runId" element={<RunDetail />} />
          <Route path="/findings" element={<Findings />} />
          <Route path="/kb" element={<KnowledgeBase />} />
          <Route path="/reports" element={<Reports />} />
        </Routes>
      </main>
    </div>
  )
}
