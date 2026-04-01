import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { api, Incident } from '../lib/api'
import { SeverityBadge } from '../components/Badges'
import ErrorState from '../components/ErrorState'
import { formatDistanceToNow, formatDateTime } from '../lib/time'

const PATTERN_ICONS: Record<string, string> = {
  brute_force: '🔑',
  lateral_movement: '↔️',
  privilege_escalation: '⬆️',
}

const PATTERN_DESC: Record<string, string> = {
  brute_force: 'Multiple failed authentication attempts from the same source',
  lateral_movement: 'Same account observed on multiple hosts',
  privilege_escalation: 'Suspicious process execution + privilege account activity',
}

function IncidentModal({ incident, onClose }: { incident: Incident; onClose: () => void }) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60" onClick={onClose}>
      <div className="bg-surface border border-border rounded-xl shadow-2xl w-full max-w-lg max-h-[85vh] overflow-y-auto" onClick={e => e.stopPropagation()}>
        <div className="sticky top-0 bg-surface border-b border-border px-6 py-4 flex items-start justify-between">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <span className="text-xl">{PATTERN_ICONS[incident.pattern_type] ?? '⚠️'}</span>
              <p className="text-white font-semibold">{incident.title}</p>
            </div>
            <p className="text-muted text-xs font-mono">{incident.id.slice(0, 16)}…</p>
          </div>
          <button onClick={onClose} className="text-muted hover:text-white text-xl ml-4">✕</button>
        </div>

        <div className="p-6 space-y-5">
          <div className="grid grid-cols-2 gap-4 text-sm">
            <div><span className="text-muted">Severity</span><div className="mt-1"><SeverityBadge severity={incident.severity} /></div></div>
            <div><span className="text-muted">Status</span><p className="text-white mt-1 capitalize">{incident.status}</p></div>
            <div><span className="text-muted">Pattern</span><p className="text-accent mt-1">{incident.pattern_type.replace(/_/g, ' ')}</p></div>
            <div><span className="text-muted">Detected</span><p className="text-white text-xs mt-1">{formatDateTime(incident.created_at)}</p></div>
          </div>

          {incident.description && (
            <div>
              <p className="text-muted text-xs font-medium uppercase tracking-wide mb-1">Description</p>
              <p className="text-white text-sm">{incident.description}</p>
            </div>
          )}

          {incident.mitre_tactics?.length > 0 && (
            <div>
              <p className="text-muted text-xs font-medium uppercase tracking-wide mb-2">MITRE Tactics</p>
              <div className="flex flex-wrap gap-2">
                {incident.mitre_tactics.map(t => (
                  <span key={t} className="px-2 py-1 bg-accent/10 text-accent border border-accent/20 rounded text-xs">{t}</span>
                ))}
              </div>
            </div>
          )}

          {incident.mitre_techniques?.length > 0 && (
            <div>
              <p className="text-muted text-xs font-medium uppercase tracking-wide mb-2">MITRE Techniques</p>
              <div className="flex flex-wrap gap-2">
                {incident.mitre_techniques.map(t => (
                  <span key={t} className="px-2 py-1 bg-danger/10 text-danger border border-danger/20 rounded text-xs font-mono">{t}</span>
                ))}
              </div>
            </div>
          )}

          {incident.alerts && incident.alerts.length > 0 && (
            <div>
              <p className="text-muted text-xs font-medium uppercase tracking-wide mb-2">Linked Alerts ({incident.alerts.length})</p>
              <div className="space-y-2">
                {incident.alerts.map(a => (
                  <div key={a.id} className="bg-bg border border-border rounded-md px-3 py-2 text-xs flex items-center justify-between">
                    <span className="text-white">{a.normalized_alert?.title ?? a.id.slice(0, 16)}</span>
                    <span className="text-muted">{formatDistanceToNow(a.created_at)}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

function IncidentCard({ incident, onClick }: { incident: Incident; onClick: () => void }) {
  return (
    <div
      onClick={onClick}
      className="bg-surface border border-border rounded-lg p-4 hover:border-accent/50 cursor-pointer transition-colors"
    >
      <div className="flex items-start justify-between mb-3">
        <div className="flex items-center gap-2">
          <span className="text-xl">{PATTERN_ICONS[incident.pattern_type] ?? '⚠️'}</span>
          <div>
            <p className="text-white text-sm font-medium leading-tight">{incident.title}</p>
            <p className="text-muted text-xs mt-0.5">{formatDistanceToNow(incident.created_at)}</p>
          </div>
        </div>
        <SeverityBadge severity={incident.severity} />
      </div>

      {incident.mitre_techniques?.length > 0 && (
        <div className="flex flex-wrap gap-1 mb-3">
          {incident.mitre_techniques.slice(0, 4).map(t => (
            <span key={t} className="px-1.5 py-0.5 bg-danger/10 text-danger border border-danger/20 rounded text-[10px] font-mono">{t}</span>
          ))}
          {incident.mitre_techniques.length > 4 && (
            <span className="text-muted text-[10px] px-1">+{incident.mitre_techniques.length - 4}</span>
          )}
        </div>
      )}

      <div className="flex items-center justify-between text-xs text-muted">
        <span className="capitalize">{incident.pattern_type.replace(/_/g, ' ')}</span>
        <span className="capitalize">{incident.status}</span>
      </div>
    </div>
  )
}

export default function Incidents() {
  const [selected, setSelected] = useState<Incident | null>(null)
  const { data: incidents, isLoading, error, refetch } = useQuery({
    queryKey: ['incidents'],
    queryFn: api.incidents,
    refetchInterval: 30_000,
  })

  if (error) return <div className="p-6"><ErrorState message={String(error)} onRetry={refetch} /></div>

  const grouped = (incidents ?? []).reduce<Record<string, Incident[]>>((acc, inc) => {
    const k = inc.pattern_type ?? 'other'
    ;(acc[k] = acc[k] ?? []).push(inc)
    return acc
  }, {})

  const patterns = ['brute_force', 'lateral_movement', 'privilege_escalation', ...Object.keys(grouped).filter(k => !['brute_force','lateral_movement','privilege_escalation'].includes(k))]

  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="text-xl font-semibold text-white">Incidents</h1>
        <p className="text-muted text-sm mt-0.5">Correlated attack patterns detected by TrustSOC</p>
      </div>

      {isLoading ? (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {Array.from({ length: 6 }).map((_, i) => (
            <div key={i} className="bg-surface border border-border rounded-lg p-4 space-y-3">
              <div className="skeleton h-4 w-2/3 rounded" />
              <div className="skeleton h-3 w-1/2 rounded" />
              <div className="skeleton h-3 w-3/4 rounded" />
            </div>
          ))}
        </div>
      ) : (incidents ?? []).length === 0 ? (
        <div className="text-center py-16 text-muted">
          <p className="text-4xl mb-3">🛡️</p>
          <p className="font-medium text-white">No incidents detected yet</p>
          <p className="text-sm mt-1">Incidents are auto-created when 3+ correlated alerts are detected</p>
        </div>
      ) : (
        patterns.filter(p => grouped[p]?.length).map(pattern => (
          <div key={pattern}>
            <div className="flex items-center gap-2 mb-3">
              <span>{PATTERN_ICONS[pattern] ?? '⚠️'}</span>
              <h2 className="text-sm font-semibold text-white capitalize">{pattern.replace(/_/g, ' ')}</h2>
              <span className="text-muted text-xs">({grouped[pattern].length})</span>
            </div>
            {PATTERN_DESC[pattern] && <p className="text-muted text-xs mb-3">{PATTERN_DESC[pattern]}</p>}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
              {grouped[pattern].map(inc => (
                <IncidentCard key={inc.id} incident={inc} onClick={() => setSelected(inc)} />
              ))}
            </div>
          </div>
        ))
      )}

      {selected && <IncidentModal incident={selected} onClose={() => setSelected(null)} />}
    </div>
  )
}
