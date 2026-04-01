export function SeverityBadge({ severity }: { severity?: string }) {
  const s = (severity ?? 'unknown').toLowerCase()
  const cls =
    s === 'critical' ? 'bg-danger/20 text-danger border-danger/40' :
    s === 'high'     ? 'bg-orange-500/20 text-orange-400 border-orange-500/40' :
    s === 'medium'   ? 'bg-warning/20 text-warning border-warning/40' :
    s === 'low'      ? 'bg-success/20 text-success border-success/40' :
                       'bg-muted/20 text-muted border-muted/40'
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border ${cls}`}>
      {s}
    </span>
  )
}

export function StatusBadge({ status }: { status?: string }) {
  const s = (status ?? '').toLowerCase()
  const cls =
    s === 'confirmed'     ? 'bg-danger/20 text-danger' :
    s === 'enriched'      ? 'bg-accent/20 text-accent' :
    s === 'false_positive'? 'bg-success/20 text-success' :
    s === 'suppressed'    ? 'bg-muted/20 text-muted' :
    s === 'under_review'  ? 'bg-warning/20 text-warning' :
                            'bg-muted/10 text-muted'
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs ${cls}`}>
      {s.replace(/_/g, ' ')}
    </span>
  )
}

export function SourceChip({ source }: { source?: string }) {
  const s = (source ?? 'generic').toLowerCase()
  const cls =
    s === 'wazuh'   ? 'bg-purple-500/20 text-purple-300' :
    s === 'elastic' ? 'bg-yellow-500/20 text-yellow-300' :
    s === 'splunk'  ? 'bg-green-500/20 text-green-300' :
                      'bg-muted/20 text-muted'
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-mono ${cls}`}>
      {s}
    </span>
  )
}

export function RiskBar({ score }: { score: number }) {
  const color =
    score >= 80 ? 'bg-danger' :
    score >= 60 ? 'bg-orange-500' :
    score >= 40 ? 'bg-warning' :
                  'bg-success'
  return (
    <div className="flex items-center gap-2">
      <div className="w-20 h-1.5 bg-border rounded-full overflow-hidden">
        <div className={`h-full rounded-full ${color}`} style={{ width: `${score}%` }} />
      </div>
      <span className="text-xs text-muted tabular-nums w-6">{score}</span>
    </div>
  )
}
