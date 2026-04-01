import { useQuery } from '@tanstack/react-query'
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts'
import { api } from '../lib/api'
import { SkeletonCard } from '../components/Skeleton'
import ErrorState from '../components/ErrorState'
import { SeverityBadge, RiskBar, StatusBadge } from '../components/Badges'
import { formatDistanceToNow } from '../lib/time'

function StatCard({ label, value, sub, accent }: { label: string; value: number | string; sub?: string; accent?: boolean }) {
  return (
    <div className="bg-surface border border-border rounded-lg p-5">
      <p className="text-muted text-xs font-medium uppercase tracking-wide">{label}</p>
      <p className={`text-3xl font-bold mt-1 ${accent ? 'text-danger' : 'text-white'}`}>{value}</p>
      {sub && <p className="text-muted text-xs mt-1">{sub}</p>}
    </div>
  )
}

const SEV_COLORS: Record<string, string> = {
  critical: '#f85149',
  high:     '#f97316',
  medium:   '#d29922',
  low:      '#3fb950',
}

export default function Overview() {
  const { data: stats, isLoading: statsLoading, error: statsError, refetch: statsRefetch } =
    useQuery({ queryKey: ['stats'], queryFn: api.stats, refetchInterval: 30_000 })

  const { data: alerts, isLoading: alertsLoading } =
    useQuery({ queryKey: ['alerts-high'], queryFn: () => api.alerts({ limit: 50, min_risk_score: 0 }), refetchInterval: 30_000 })

  // Severity distribution from alert data
  const sevCounts = (alerts ?? []).reduce<Record<string, number>>((acc, a) => {
    const sev = a.normalized_alert?.severity ?? 'unknown'
    acc[sev] = (acc[sev] ?? 0) + 1
    return acc
  }, {})
  const sevData = ['critical', 'high', 'medium', 'low'].map(s => ({ name: s, count: sevCounts[s] ?? 0 }))

  const highRiskAlerts = (alerts ?? [])
    .filter(a => a.risk_score >= 70)
    .sort((a, b) => b.risk_score - a.risk_score)
    .slice(0, 10)

  if (statsError) return <div className="p-6"><ErrorState message={String(statsError)} onRetry={statsRefetch} /></div>

  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="text-xl font-semibold text-white">Overview</h1>
        <p className="text-muted text-sm mt-0.5">Live security operations dashboard · auto-refreshes every 30s</p>
      </div>

      {/* Stat cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {statsLoading ? (
          Array.from({ length: 4 }).map((_, i) => <SkeletonCard key={i} />)
        ) : (
          <>
            <StatCard label="Total Alerts" value={stats!.total_alerts} sub="all time" />
            <StatCard label="Alerts (24h)" value={stats!.alerts_24h} sub="last 24 hours" />
            <StatCard label="Incidents (24h)" value={stats!.incidents_24h} sub="correlated groups" />
            <StatCard label="High-Risk Open" value={stats!.high_risk_open} sub="score ≥ 70, unresolved" accent />
          </>
        )}
      </div>

      {/* Severity distribution */}
      <div className="bg-surface border border-border rounded-lg p-5">
        <h2 className="text-sm font-semibold text-white mb-4">Alert Severity Distribution</h2>
        {alertsLoading ? (
          <div className="h-32 skeleton rounded" />
        ) : (
          <ResponsiveContainer width="100%" height={130}>
            <BarChart data={sevData} barSize={40}>
              <XAxis dataKey="name" tick={{ fill: '#8b949e', fontSize: 12 }} axisLine={false} tickLine={false} />
              <YAxis tick={{ fill: '#8b949e', fontSize: 12 }} axisLine={false} tickLine={false} />
              <Tooltip
                contentStyle={{ background: '#161b22', border: '1px solid #30363d', borderRadius: 6, color: '#c9d1d9' }}
                cursor={{ fill: 'rgba(255,255,255,0.04)' }}
              />
              <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                {sevData.map(entry => (
                  <Cell key={entry.name} fill={SEV_COLORS[entry.name] ?? '#8b949e'} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        )}
      </div>

      {/* Recent high-risk alerts */}
      <div className="bg-surface border border-border rounded-lg overflow-hidden">
        <div className="px-5 py-4 border-b border-border">
          <h2 className="text-sm font-semibold text-white">Recent High-Risk Alerts</h2>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border">
                {['Severity', 'Title', 'Host', 'Risk', 'Status', 'Time'].map(h => (
                  <th key={h} className="px-4 py-2 text-left text-xs font-medium text-muted">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {alertsLoading ? (
                Array.from({ length: 5 }).map((_, i) => (
                  <tr key={i} className="border-b border-border/50">
                    {Array.from({ length: 6 }).map((_, j) => (
                      <td key={j} className="px-4 py-3"><div className="skeleton h-4 rounded" /></td>
                    ))}
                  </tr>
                ))
              ) : highRiskAlerts.length === 0 ? (
                <tr><td colSpan={6} className="px-4 py-8 text-center text-muted text-sm">No high-risk alerts yet</td></tr>
              ) : (
                highRiskAlerts.map(a => (
                  <tr key={a.id} className="border-b border-border/50 hover:bg-white/[0.02] transition-colors">
                    <td className="px-4 py-3"><SeverityBadge severity={a.normalized_alert?.severity} /></td>
                    <td className="px-4 py-3 text-white max-w-xs truncate">{a.normalized_alert?.title ?? '—'}</td>
                    <td className="px-4 py-3 text-muted font-mono text-xs">{a.normalized_alert?.source_host ?? a.normalized_alert?.source_ip ?? '—'}</td>
                    <td className="px-4 py-3"><RiskBar score={a.risk_score} /></td>
                    <td className="px-4 py-3"><StatusBadge status={a.status} /></td>
                    <td className="px-4 py-3 text-muted text-xs">{formatDistanceToNow(a.created_at)}</td>
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
