import { useState } from 'react'
import { useMutation } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import {
  Crosshair,
  Globe,
  Server,
  Shield,
  Zap,
} from 'lucide-react'
import { runsApi } from '../lib/api'

const modes = [
  {
    value: 'black_box',
    label: 'Black Box',
    description: 'No prior knowledge. Simulates an external attacker.',
    icon: Shield,
  },
  {
    value: 'gray_box',
    label: 'Gray Box',
    description: 'Partial knowledge (e.g. API docs, limited credentials).',
    icon: Server,
  },
  {
    value: 'white_box',
    label: 'White Box',
    description: 'Full access to source code, architecture docs, and credentials.',
    icon: Globe,
  },
]

export default function NewRun() {
  const navigate = useNavigate()
  const [name, setName] = useState('')
  const [mode, setMode] = useState('black_box')
  const [objective, setObjective] = useState('')
  const [domains, setDomains] = useState('')
  const [ips, setIps] = useState('')
  const [urls, setUrls] = useState('')
  const [autoStart, setAutoStart] = useState(true)

  const createMutation = useMutation({
    mutationFn: async () => {
      const targets: { target_type: string; value: string }[] = [
        ...domains.split('\n').filter(Boolean).map((d) => ({ target_type: 'domain', value: d.trim() })),
        ...ips.split('\n').filter(Boolean).map((i) => ({ target_type: 'ip', value: i.trim() })),
        ...urls.split('\n').filter(Boolean).map((u) => ({ target_type: 'url', value: u.trim() })),
      ]

      const run = await runsApi.create({
        name,
        config: { mode, objective },
        targets,
      })

      if (autoStart) {
        await runsApi.start(run.id)
      }

      return run
    },
    onSuccess: (run) => {
      navigate(`/runs/${run.id}`)
    },
  })

  return (
    <div className="p-8 max-w-3xl mx-auto space-y-8">
      <div>
        <h1 className="text-3xl font-bold flex items-center gap-3">
          <Zap className="h-8 w-8 text-primary" />
          New Run
        </h1>
        <p className="text-muted-foreground mt-1">
          Configure a new red-team engagement
        </p>
      </div>

      {/* Run Name */}
      <div className="space-y-2">
        <label className="text-sm font-medium">Run Name</label>
        <input
          type="text"
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="e.g. Q4 External Assessment"
          className="w-full bg-background border border-border rounded-md px-3 py-2 text-sm"
        />
      </div>

      {/* Mode Selector */}
      <div className="space-y-2">
        <label className="text-sm font-medium">Engagement Mode</label>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
          {modes.map((m) => {
            const Icon = m.icon
            const isSelected = mode === m.value
            return (
              <button
                key={m.value}
                onClick={() => setMode(m.value)}
                className={`border rounded-lg p-4 text-left transition-all ${
                  isSelected
                    ? 'border-primary bg-primary/5 ring-1 ring-primary'
                    : 'border-border hover:border-muted-foreground'
                }`}
              >
                <Icon className={`h-5 w-5 mb-2 ${isSelected ? 'text-primary' : 'text-muted-foreground'}`} />
                <p className="font-medium text-sm">{m.label}</p>
                <p className="text-xs text-muted-foreground mt-1">{m.description}</p>
              </button>
            )
          })}
        </div>
      </div>

      {/* Objective */}
      <div className="space-y-2">
        <label className="text-sm font-medium">Objective</label>
        <textarea
          value={objective}
          onChange={(e) => setObjective(e.target.value)}
          rows={3}
          placeholder="Describe what the red-team engagement should focus on..."
          className="w-full bg-background border border-border rounded-md px-3 py-2 text-sm resize-none"
        />
      </div>

      {/* Scope Definition */}
      <div className="space-y-4">
        <label className="text-sm font-medium flex items-center gap-2">
          <Crosshair className="h-4 w-4" />
          Scope Definition
        </label>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="space-y-1">
            <label className="text-xs text-muted-foreground">Domains (one per line)</label>
            <textarea
              value={domains}
              onChange={(e) => setDomains(e.target.value)}
              rows={4}
              placeholder={"example.com\n*.example.com"}
              className="w-full bg-background border border-border rounded-md px-3 py-2 text-xs font-mono resize-none"
            />
          </div>
          <div className="space-y-1">
            <label className="text-xs text-muted-foreground">IP Ranges (one per line)</label>
            <textarea
              value={ips}
              onChange={(e) => setIps(e.target.value)}
              rows={4}
              placeholder={"10.0.0.0/24\n192.168.1.100"}
              className="w-full bg-background border border-border rounded-md px-3 py-2 text-xs font-mono resize-none"
            />
          </div>
          <div className="space-y-1">
            <label className="text-xs text-muted-foreground">URLs (one per line)</label>
            <textarea
              value={urls}
              onChange={(e) => setUrls(e.target.value)}
              rows={4}
              placeholder={"https://api.example.com\nhttps://app.example.com"}
              className="w-full bg-background border border-border rounded-md px-3 py-2 text-xs font-mono resize-none"
            />
          </div>
        </div>
      </div>

      {/* Auto-start toggle */}
      <div className="flex items-center gap-3">
        <button
          onClick={() => setAutoStart(!autoStart)}
          className={`relative w-11 h-6 rounded-full transition-colors ${
            autoStart ? 'bg-primary' : 'bg-muted'
          }`}
        >
          <span
            className={`absolute top-0.5 left-0.5 w-5 h-5 bg-white rounded-full transition-transform ${
              autoStart ? 'translate-x-5' : 'translate-x-0'
            }`}
          />
        </button>
        <span className="text-sm">Start run immediately after creation</span>
      </div>

      {/* Submit */}
      {createMutation.isError && (
        <div className="bg-red-500/10 border border-red-500/30 rounded-md p-3 text-red-400 text-sm">
          Failed to create run. Please try again.
        </div>
      )}

      <button
        onClick={() => createMutation.mutate()}
        disabled={!name || createMutation.isPending}
        className="w-full py-3 bg-primary text-primary-foreground rounded-md font-medium hover:bg-primary/90 disabled:opacity-50 transition-colors"
      >
        {createMutation.isPending ? 'Creating Run...' : 'Launch Red-Team Run'}
      </button>
    </div>
  )
}
