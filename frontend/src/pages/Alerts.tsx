import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api, Alert, EvidenceBundle } from '../lib/api'
import { SeverityBadge, StatusBadge, SourceChip, RiskBar } from '../components/Badges'
import { SkeletonRow } from '../components/Skeleton'
import ErrorState from '../components/ErrorState'
import { formatDistanceToNow, formatDateTime } from '../lib/time'

// ── Detail slide-out panel ────────────────────────────────────────────────────
function AlertPanel({ alert, onClose }: { alert: Alert; onClose: () => void }) {
  const { data: evidence, isLoading } = useQuery({
    queryKey: ['evidence', alert.id],
    queryFn: () => api.evidence(alert.id),
  })
  const qc = useQueryClient()
  const feedbackMutation = useMutation({
    mutationFn: (ft: string) => api.submitFeedback(alert.id, { feedback_type: ft, analyst_id: 'dashboard' }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['alerts'] }); qc.invalidateQueries({ queryKey: ['alerts-high'] }) },
  })

  const n = alert.normalized_alert ?? {}

  return (
    <div className="fixed inset-0 z-40 flex justify-end" onClick={onClose}>
      <div className="w-full max-w-xl bg-surface border-l border-border h-full overflow-y-auto shadow-2xl" onClick={e => e.stopPropagation()}>
        <div className="sticky top-0 bg-surface border-b border-border px-5 py-4 flex items-start justify-between">
          <div>
            <p className="text-white font-semibold text-sm">{n.title ?? 'Alert Detail'}</p>
            <p className="text-muted text-xs mt-0.5 font-mono">{alert.id.slice(0, 16)}…</p>
          </div>
          <button onClick={onClose} className="text-muted hover:text-white text-xl leading-none mt-0.5">✕</button>
        </div>

        <div className="p-5 space-y-5">
          {/* Meta */}
          <div className="grid grid-cols-2 gap-3 text-sm">
            <div><span className="text-muted">Source</span><div className="mt-1"><SourceChip source={alert.source_system} /></div></div>
            <div><span className="text-muted">Severity</span><div className="mt-1"><SeverityBadge severity={n.severity} /></div></div>
            <div><span className="text-muted">Risk Score</span><div className="mt-1"><RiskBar score={alert.risk_score} /></div></div>
            <div><span className="text-muted">Status</span><div className="mt-1"><StatusBadge status={alert.status} /></div></div>
            <div><span className="text-muted">Host</span><p className="text-white font-mono text-xs mt-1">{n.source_host ?? '—'}</p></div>
            <div><span className="text-muted">Source IP</span><p className="text-white font-mono text-xs mt-1">{n.source_ip ?? '—'}</p></div>
          </div>

          {/* Feedback */}
          <div>
            <p className="text-muted text-xs font-medium uppercase tracking-wide mb-2">Analyst Feedback</p>
            <div className="flex gap-2">
              {[['true_positive', 'TP', 'bg-danger/20 text-danger border-danger/40'],
                ['false_positive', 'FP', 'bg-success/20 text-success border-success/40'],
                ['benign', 'Benign', 'bg-warning/20 text-warning border-warning/40']].map(([ft, label, cls]) => (
                <button
                  key={ft}
                  onClick={() => feedbackMutation.mutate(ft)}
                  disabled={feedbackMutation.isPending}
                  className={`px-3 py-1.5 rounded text-xs font-medium border transition-opacity ${cls} hover:opacity-80 disabled:opacity-40`}
                >
                  {label}
                </button>
              ))}
            </div>
            {feedbackMutation.isSuccess && <p className="text-success text-xs mt-1">Feedback recorded</p>}
          </div>

          {/* IOCs */}
          {n.iocs && Object.keys(n.iocs).length > 0 && (
            <div>
              <p className="text-muted text-xs font-medium uppercase tracking-wide mb-2">IOCs Extracted</p>
              <div className="space-y-1">
                {Object.entries(n.iocs).map(([type, vals]) =>
                  (vals as string[]).map(v => (
                    <div key={v} className="flex items-center gap-2 text-xs">
                      <span className="text-muted font-mono w-12">{type}</span>
                      <span className="text-accent font-mono">{v}</span>
                    </div>
                  ))
                )}
              </div>
            </div>
          )}

          {/* Evidence chain */}
          <div>
            <p className="text-muted text-xs font-medium uppercase tracking-wide mb-3">Evidence Chain</p>
            {isLoading ? (
              <div className="space-y-2">{Array.from({ length: 3 }).map((_, i) => <div key={i} className="skeleton h-12 rounded" />)}</div>
            ) : (
              <EvidenceTimeline bundle={evidence} />
            )}
          </div>
        </div>
      </div>
    </div>
  )
}

const EV_ICONS: Record<string, string> = {
  alert_received: '📥',
  enrichment_completed: '🔬',
  correlation_detected: '🔗',
  analyst_feedback: '👤',
  policy_executed: '📋',
  suppression_applied: '🔕',
  suppression_auto_created: '🤖',
  action_executed: '⚡',
}

function EvidenceTimeline({ bundle }: { bundle?: EvidenceBundle }) {
  const [expanded, setExpanded] = useState<string | null>(null)
  if (!bundle) return <p className="text-muted text-sm">No evidence data</p>
  return (
    <div className="relative space-y-3 pl-6 before:absolute before:left-2 before:top-0 before:bottom-0 before:w-px before:bg-border">
      {bundle.evidence_trail.map(ev => (
        <div key={ev.id} className="relative">
          <div className="absolute -left-6 top-0 w-4 h-4 rounded-full bg-surface border border-accent flex items-center justify-center text-[8px]">
            {EV_ICONS[ev.evidence_type] ?? '•'}
          </div>
          <div className="bg-bg border border-border rounded-md p-3 text-xs">
            <div className="flex items-center justify-between mb-1">
              <span className="text-accent font-medium">{ev.evidence_type.replace(/_/g, ' ')}</span>
              <span className="text-muted">{formatDistanceToNow(ev.collected_at)}</span>
            </div>
            <button
              onClick={() => setExpanded(expanded === ev.id ? null : ev.id)}
              className="text-muted hover:text-white text-xs"
            >
              {expanded === ev.id ? '▲ hide details' : '▼ show details'}
            </button>
            {expanded === ev.id && (
              <pre className="mt-2 text-muted overflow-x-auto text-[10px] leading-relaxed">
                {JSON.stringify(ev.evidence_data, null, 2)}
              </pre>
            )}
          </div>
        </div>
      ))}
    </div>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────
export default function Alerts() {
  const [severity, setSeverity] = useState('')
  const [status, setStatus] = useState('')
  const [minScore, setMinScore] = useState(0)
  const [selected, setSelected] = useState<Alert | null>(null)

  const { data: alerts, isLoading, error, refetch } = useQuery({
    queryKey: ['alerts', severity, status, minScore],
    queryFn: () => api.alerts({ limit: 100, min_risk_score: minScore, alert_status: status || undefined }),
    refetchInterval: 30_000,
  })

  const filtered = (alerts ?? []).filter(a =>
    !severity || (a.normalized_alert?.severity ?? '').toLowerCase() === severity
  )

  return (
    <div className="p-6 space-y-4">
      <div>
        <h1 className="text-xl font-semibold text-white">Alert Feed</h1>
        <p className="text-muted text-sm mt-0.5">All ingested alerts with enrichment · click row for details</p>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap gap-3 items-center">
        <select
          value={severity} onChange={e => setSeverity(e.target.value)}
          className="bg-surface border border-border text-white text-sm rounded-md px-3 py-1.5 focus:outline-none focus:border-accent"
        >
          <option value="">All Severities</option>
          {['critical','high','medium','low'].map(s => <option key={s} value={s}>{s}</option>)}
        </select>
        <select
          value={status} onChange={e => setStatus(e.target.value)}
          className="bg-surface border border-border text-white text-sm rounded-md px-3 py-1.5 focus:outline-none focus:border-accent"
        >
          <option value="">All Statuses</option>
          {['enriched','confirmed','false_positive','suppressed','under_review','processing'].map(s => (
            <option key={s} value={s}>{s.replace(/_/g,' ')}</option>
          ))}
        </select>
        <div className="flex items-center gap-2 text-sm text-muted">
          <span>Min score:</span>
          <input
            type="range" min={0} max={100} step={10} value={minScore}
            onChange={e => setMinScore(Number(e.target.value))}
            className="w-24 accent-accent"
          />
          <span className="text-white w-6 tabular-nums">{minScore}</span>
        </div>
        <span className="text-muted text-xs ml-auto">{filtered.length} results</span>
      </div>

      {/* Table */}
      {error ? (
        <ErrorState message={String(error)} onRetry={refetch} />
      ) : (
        <div className="bg-surface border border-border rounded-lg overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border">
                  {['Sev', 'Source', 'Title', 'Host', 'Risk', 'Status', 'Time'].map(h => (
                    <th key={h} className="px-4 py-2.5 text-left text-xs font-medium text-muted">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {isLoading
                  ? Array.from({ length: 8 }).map((_, i) => <SkeletonRow key={i} />)
                  : filtered.length === 0
                  ? <tr><td colSpan={7} className="px-4 py-10 text-center text-muted">No alerts match your filters</td></tr>
                  : filtered.map(a => (
                    <tr
                      key={a.id}
                      onClick={() => setSelected(a)}
                      className="border-b border-border/50 hover:bg-white/[0.03] cursor-pointer transition-colors"
                    >
                      <td className="px-4 py-3"><SeverityBadge severity={a.normalized_alert?.severity} /></td>
                      <td className="px-4 py-3"><SourceChip source={a.source_system} /></td>
                      <td className="px-4 py-3 text-white max-w-xs truncate">{a.normalized_alert?.title ?? '—'}</td>
                      <td className="px-4 py-3 text-muted font-mono text-xs">{a.normalized_alert?.source_host ?? '—'}</td>
                      <td className="px-4 py-3"><RiskBar score={a.risk_score} /></td>
                      <td className="px-4 py-3"><StatusBadge status={a.status} /></td>
                      <td className="px-4 py-3 text-muted text-xs">{formatDistanceToNow(a.created_at)}</td>
                    </tr>
                  ))
                }
              </tbody>
            </table>
          </div>
        </div>
      )}

      {selected && <AlertPanel alert={selected} onClose={() => setSelected(null)} />}
    </div>
  )
}
