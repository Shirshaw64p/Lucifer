import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import {
  AlertTriangle,
  ChevronDown,
  ChevronUp,
  Filter,
  Search,
  X,
} from 'lucide-react'
import { runsApi, findingsApi, type Run, type Finding, type FindingDetail } from '../lib/api'

const severityColors: Record<string, string> = {
  critical: 'bg-red-500 text-white',
  high: 'bg-orange-500 text-white',
  medium: 'bg-yellow-500 text-black',
  low: 'bg-blue-500 text-white',
  info: 'bg-gray-500 text-white',
}

const severityOrder: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
}

export default function Findings() {
  const [selectedRunId, setSelectedRunId] = useState<string>('')
  const [severityFilter, setSeverityFilter] = useState<string>('')
  const [searchQuery, setSearchQuery] = useState<string>('')
  const [sortField, setSortField] = useState<'severity' | 'created_at'>('severity')
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('asc')
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null)

  const { data: runs = [] } = useQuery({
    queryKey: ['runs'],
    queryFn: runsApi.list,
  })

  const { data: findings = [] } = useQuery({
    queryKey: ['findings', selectedRunId],
    queryFn: () => findingsApi.list(selectedRunId, severityFilter || undefined),
    enabled: !!selectedRunId,
    refetchInterval: 5000,
  })

  const filtered = findings
    .filter((f: Finding) => {
      if (searchQuery && !f.title.toLowerCase().includes(searchQuery.toLowerCase())) return false
      if (severityFilter && f.severity !== severityFilter) return false
      return true
    })
    .sort((a: Finding, b: Finding) => {
      if (sortField === 'severity') {
        const diff = (severityOrder[a.severity] ?? 5) - (severityOrder[b.severity] ?? 5)
        return sortDir === 'asc' ? diff : -diff
      }
      const diff = new Date(a.created_at).getTime() - new Date(b.created_at).getTime()
      return sortDir === 'asc' ? diff : -diff
    })

  const toggleSort = (field: 'severity' | 'created_at') => {
    if (sortField === field) {
      setSortDir((d) => (d === 'asc' ? 'desc' : 'asc'))
    } else {
      setSortField(field)
      setSortDir('asc')
    }
  }

  const SortIcon = ({ field }: { field: string }) => {
    if (sortField !== field) return null
    return sortDir === 'asc' ? <ChevronUp className="h-3 w-3" /> : <ChevronDown className="h-3 w-3" />
  }

  return (
    <div className="p-8 space-y-6">
      <div>
        <h1 className="text-3xl font-bold">Findings</h1>
        <p className="text-muted-foreground mt-1">All vulnerabilities discovered across runs</p>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap gap-3">
        <select
          value={selectedRunId}
          onChange={(e) => setSelectedRunId(e.target.value)}
          className="bg-background border border-border rounded-md px-3 py-2 text-sm"
        >
          <option value="">Select a run...</option>
          {runs.map((r: Run) => (
            <option key={r.id} value={r.id}>
              {r.name} ({r.status})
            </option>
          ))}
        </select>

        <select
          value={severityFilter}
          onChange={(e) => setSeverityFilter(e.target.value)}
          className="bg-background border border-border rounded-md px-3 py-2 text-sm"
        >
          <option value="">All severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
          <option value="info">Info</option>
        </select>

        <div className="relative flex-1 min-w-[200px]">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <input
            type="text"
            placeholder="Search findings..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full bg-background border border-border rounded-md pl-10 pr-3 py-2 text-sm"
          />
        </div>
      </div>

      {!selectedRunId ? (
        <div className="bg-card border border-border rounded-lg p-12 text-center text-muted-foreground">
          <AlertTriangle className="h-12 w-12 mx-auto mb-4 opacity-50" />
          <p>Select a run above to view its findings.</p>
        </div>
      ) : (
        <div className="bg-card border border-border rounded-lg overflow-hidden">
          <table className="w-full">
            <thead>
              <tr className="border-b border-border text-left">
                <th
                  className="px-6 py-3 text-xs font-medium text-muted-foreground uppercase tracking-wider cursor-pointer hover:text-foreground"
                  onClick={() => toggleSort('severity')}
                >
                  <span className="flex items-center gap-1">
                    Severity <SortIcon field="severity" />
                  </span>
                </th>
                <th className="px-6 py-3 text-xs font-medium text-muted-foreground uppercase tracking-wider">
                  Title
                </th>
                <th className="px-6 py-3 text-xs font-medium text-muted-foreground uppercase tracking-wider">
                  CVSS
                </th>
                <th
                  className="px-6 py-3 text-xs font-medium text-muted-foreground uppercase tracking-wider cursor-pointer hover:text-foreground"
                  onClick={() => toggleSort('created_at')}
                >
                  <span className="flex items-center gap-1">
                    Created <SortIcon field="created_at" />
                  </span>
                </th>
                <th className="px-6 py-3 text-xs font-medium text-muted-foreground uppercase tracking-wider">
                  Actions
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {filtered.length === 0 ? (
                <tr>
                  <td colSpan={5} className="px-6 py-12 text-center text-muted-foreground">
                    No findings match the current filters.
                  </td>
                </tr>
              ) : (
                filtered.map((f: Finding) => (
                  <tr key={f.id} className="hover:bg-muted/30 transition-colors">
                    <td className="px-6 py-3">
                      <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${severityColors[f.severity]}`}>
                        {f.severity}
                      </span>
                    </td>
                    <td className="px-6 py-3 font-medium text-sm">{f.title}</td>
                    <td className="px-6 py-3 text-sm text-muted-foreground">
                      {f.cvss_score != null ? f.cvss_score.toFixed(1) : '—'}
                    </td>
                    <td className="px-6 py-3 text-sm text-muted-foreground">
                      {new Date(f.created_at).toLocaleString()}
                    </td>
                    <td className="px-6 py-3">
                      <button
                        onClick={() => setSelectedFinding(f)}
                        className="text-primary text-sm hover:underline"
                      >
                        Details
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      )}

      {/* Finding Modal */}
      {selectedFinding && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-8">
          <div className="bg-card border border-border rounded-lg max-w-3xl w-full max-h-[85vh] overflow-y-auto">
            <div className="sticky top-0 bg-card border-b border-border p-6 flex items-center justify-between">
              <div className="flex items-center gap-3">
                <h2 className="text-xl font-bold">{selectedFinding.title}</h2>
                <span className={`px-2.5 py-0.5 rounded-full text-xs font-medium ${severityColors[selectedFinding.severity]}`}>
                  {selectedFinding.severity}
                </span>
              </div>
              <button onClick={() => setSelectedFinding(null)} className="text-muted-foreground hover:text-foreground">
                <X className="h-5 w-5" />
              </button>
            </div>
            <div className="p-6 space-y-6 text-sm">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <span className="text-xs text-muted-foreground block mb-1">CVSS Score</span>
                  <span className="font-medium">{selectedFinding.cvss_score ?? 'N/A'}</span>
                </div>
                <div>
                  <span className="text-xs text-muted-foreground block mb-1">Created</span>
                  <span className="font-medium">{new Date(selectedFinding.created_at).toLocaleString()}</span>
                </div>
              </div>

              <div>
                <h3 className="font-semibold text-muted-foreground mb-2">Description</h3>
                <p className="whitespace-pre-wrap">{selectedFinding.description}</p>
              </div>

              {selectedFinding.remediation && (
                <div>
                  <h3 className="font-semibold text-muted-foreground mb-2">Remediation</h3>
                  <p className="whitespace-pre-wrap">{selectedFinding.remediation}</p>
                </div>
              )}

              {selectedFinding.raw_output && (
                <div>
                  <h3 className="font-semibold text-muted-foreground mb-2">Raw Output / Evidence</h3>
                  <pre className="bg-background p-4 rounded text-xs overflow-x-auto max-h-[300px]">
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
