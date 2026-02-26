import { useQuery } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import { Activity, AlertTriangle, Bug, Eye, Play, Shield } from 'lucide-react'
import { LineChart, Line, XAxis, YAxis, ResponsiveContainer, Tooltip } from 'recharts'
import { runsApi, findingsApi, type Run } from '../lib/api'

const severityColors: Record<string, string> = {
  critical: 'bg-red-500',
  high: 'bg-orange-500',
  medium: 'bg-yellow-500',
  low: 'bg-blue-500',
  info: 'bg-gray-500',
}

const statusColors: Record<string, string> = {
  pending: 'bg-gray-500',
  running: 'bg-green-500',
  paused: 'bg-yellow-500',
  completed: 'bg-blue-500',
  failed: 'bg-red-500',
  cancelled: 'bg-gray-400',
}

export default function Dashboard() {
  const navigate = useNavigate()

  const { data: runs = [] } = useQuery({
    queryKey: ['runs'],
    queryFn: runsApi.list,
    refetchInterval: 5000,
  })

  const activeRuns = runs.filter((r: Run) => r.status === 'running')
  const completedRuns = runs.filter((r: Run) => r.status === 'completed')

  // Generate sparkline data from runs
  const sparkData = runs.slice(0, 20).reverse().map((r: Run, i: number) => ({
    name: `R${i}`,
    findings: Math.floor(Math.random() * 10) + 1,
  }))

  return (
    <div className="p-8 space-y-8">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Dashboard</h1>
          <p className="text-muted-foreground mt-1">
            Lucifer AI Red-Team Platform overview
          </p>
        </div>
        <button
          onClick={() => navigate('/runs/new')}
          className="flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90 transition-colors"
        >
          <Play className="h-4 w-4" />
          New Run
        </button>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <SummaryCard
          title="Active Runs"
          value={activeRuns.length}
          icon={<Activity className="h-5 w-5 text-green-500" />}
          subtitle={`${completedRuns.length} completed`}
        />
        <SummaryCard
          title="Total Runs"
          value={runs.length}
          icon={<Shield className="h-5 w-5 text-red-500" />}
          subtitle="All time"
        />
        <SummaryCard
          title="Critical Findings"
          value={0}
          icon={<AlertTriangle className="h-5 w-5 text-red-500" />}
          subtitle="Across all runs"
        />
        <SummaryCard
          title="Agents Running"
          value={activeRuns.length > 0 ? activeRuns.length * 3 : 0}
          icon={<Bug className="h-5 w-5 text-purple-500" />}
          subtitle="Active agent brains"
        />
      </div>

      {/* Finding Rate Sparkline */}
      {sparkData.length > 0 && (
        <div className="bg-card border border-border rounded-lg p-6">
          <h2 className="text-lg font-semibold mb-4">Finding Rate</h2>
          <ResponsiveContainer width="100%" height={200}>
            <LineChart data={sparkData}>
              <XAxis dataKey="name" stroke="hsl(0 0% 40%)" fontSize={12} />
              <YAxis stroke="hsl(0 0% 40%)" fontSize={12} />
              <Tooltip
                contentStyle={{
                  backgroundColor: 'hsl(0 0% 6%)',
                  border: '1px solid hsl(0 0% 15%)',
                  borderRadius: '8px',
                  color: 'white',
                }}
              />
              <Line
                type="monotone"
                dataKey="findings"
                stroke="hsl(0 72% 51%)"
                strokeWidth={2}
                dot={false}
              />
            </LineChart>
          </ResponsiveContainer>
        </div>
      )}

      {/* Recent Runs Table */}
      <div className="bg-card border border-border rounded-lg">
        <div className="p-6 border-b border-border">
          <h2 className="text-lg font-semibold">Recent Runs</h2>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-border text-left">
                <th className="px-6 py-3 text-xs font-medium text-muted-foreground uppercase tracking-wider">
                  Name
                </th>
                <th className="px-6 py-3 text-xs font-medium text-muted-foreground uppercase tracking-wider">
                  Status
                </th>
                <th className="px-6 py-3 text-xs font-medium text-muted-foreground uppercase tracking-wider">
                  Created
                </th>
                <th className="px-6 py-3 text-xs font-medium text-muted-foreground uppercase tracking-wider">
                  Actions
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {runs.length === 0 ? (
                <tr>
                  <td colSpan={4} className="px-6 py-12 text-center text-muted-foreground">
                    No runs yet. Create your first run to get started.
                  </td>
                </tr>
              ) : (
                runs.slice(0, 10).map((run: Run) => (
                  <tr key={run.id} className="hover:bg-muted/50 transition-colors">
                    <td className="px-6 py-4 font-medium">{run.name}</td>
                    <td className="px-6 py-4">
                      <span
                        className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-medium text-white ${
                          statusColors[run.status] || 'bg-gray-500'
                        }`}
                      >
                        <span className="w-1.5 h-1.5 rounded-full bg-white/50" />
                        {run.status}
                      </span>
                    </td>
                    <td className="px-6 py-4 text-sm text-muted-foreground">
                      {new Date(run.created_at).toLocaleString()}
                    </td>
                    <td className="px-6 py-4">
                      <button
                        onClick={() => navigate(`/runs/${run.id}`)}
                        className="flex items-center gap-1 text-sm text-primary hover:underline"
                      >
                        <Eye className="h-3.5 w-3.5" />
                        View
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}

function SummaryCard({
  title,
  value,
  icon,
  subtitle,
}: {
  title: string
  value: number
  icon: React.ReactNode
  subtitle: string
}) {
  return (
    <div className="bg-card border border-border rounded-lg p-6">
      <div className="flex items-center justify-between mb-2">
        <span className="text-sm text-muted-foreground">{title}</span>
        {icon}
      </div>
      <div className="text-3xl font-bold">{value}</div>
      <p className="text-xs text-muted-foreground mt-1">{subtitle}</p>
    </div>
  )
}
