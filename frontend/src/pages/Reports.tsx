import { useQuery } from '@tanstack/react-query'
import { FileText, Download, CheckCircle } from 'lucide-react'
import { runsApi, reportsApi, type Run } from '../lib/api'

export default function Reports() {
  const { data: runs = [] } = useQuery({
    queryKey: ['runs'],
    queryFn: () => runsApi.list(),
  })

  const completedRuns = runs.filter((r: Run) => r.status === 'completed')

  const handleDownload = (runId: string) => {
    reportsApi.download(runId)
  }

  return (
    <div className="p-8 space-y-8">
      <div>
        <h1 className="text-3xl font-bold flex items-center gap-3">
          <FileText className="h-8 w-8 text-primary" />
          Reports
        </h1>
        <p className="text-muted-foreground mt-1">
          Download findings reports for completed engagements
        </p>
      </div>

      <div className="bg-card border border-border rounded-lg">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-border text-left">
                <th className="px-6 py-3 text-xs font-medium text-muted-foreground uppercase">
                  Run Name
                </th>
                <th className="px-6 py-3 text-xs font-medium text-muted-foreground uppercase">
                  Status
                </th>
                <th className="px-6 py-3 text-xs font-medium text-muted-foreground uppercase">
                  Completed At
                </th>
                <th className="px-6 py-3 text-xs font-medium text-muted-foreground uppercase text-right">
                  Actions
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {completedRuns.length === 0 ? (
                <tr>
                  <td colSpan={4} className="px-6 py-16 text-center">
                    <FileText className="h-12 w-12 mx-auto mb-3 text-muted-foreground/50" />
                    <p className="text-muted-foreground">
                      No completed runs yet. Reports will appear here once a run finishes.
                    </p>
                  </td>
                </tr>
              ) : (
                completedRuns.map((run: Run) => (
                  <tr key={run.id} className="hover:bg-muted/30 transition-colors">
                    <td className="px-6 py-4">
                      <p className="font-medium text-sm">{run.name}</p>
                      <p className="text-xs text-muted-foreground font-mono">
                        {run.id.slice(0, 8)}...
                      </p>
                    </td>
                    <td className="px-6 py-4">
                      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium bg-green-500/10 text-green-400">
                        <CheckCircle className="h-3 w-3" />
                        Completed
                      </span>
                    </td>
                    <td className="px-6 py-4 text-sm text-muted-foreground">
                      {new Date(run.updated_at).toLocaleString()}
                    </td>
                    <td className="px-6 py-4 text-right">
                      <button
                        onClick={() => handleDownload(run.id)}
                        className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-primary text-primary-foreground rounded-md text-sm hover:bg-primary/90 transition-colors"
                      >
                        <Download className="h-4 w-4" />
                        Download
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Info Card */}
      <div className="bg-muted/30 border border-border rounded-lg p-6">
        <h3 className="font-semibold mb-2">About Reports</h3>
        <ul className="text-sm text-muted-foreground space-y-1">
          <li>• Reports include all findings, evidence references, and remediation guidance</li>
          <li>• Generated in JSON format — can be imported into your ticketing system</li>
          <li>• Reports are generated on-demand from the latest data</li>
        </ul>
      </div>
    </div>
  )
}
