import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { api, EvidenceBundle, EvidenceVerify } from '../lib/api'
import ErrorState from '../components/ErrorState'
import { formatDateTime } from '../lib/time'

const EV_ICONS: Record<string, { icon: string; color: string }> = {
  alert_received:           { icon: '📥', color: 'border-accent' },
  enrichment_completed:     { icon: '🔬', color: 'border-accent' },
  correlation_detected:     { icon: '🔗', color: 'border-warning' },
  analyst_feedback:         { icon: '👤', color: 'border-success' },
  policy_executed:          { icon: '📋', color: 'border-muted' },
  suppression_applied:      { icon: '🔕', color: 'border-muted' },
  suppression_auto_created: { icon: '🤖', color: 'border-warning' },
  action_executed:          { icon: '⚡', color: 'border-danger' },
}

function VerifyBadge({ valid }: { valid: boolean }) {
  return valid
    ? <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs bg-success/20 text-success border border-success/30">✓ Verified</span>
    : <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs bg-danger/20 text-danger border border-danger/30">✗ TAMPERED</span>
}

function EvidenceStep({
  ev,
  verify,
}: {
  ev: EvidenceBundle['evidence_trail'][number]
  verify?: EvidenceVerify
}) {
  const [expanded, setExpanded] = useState(false)
  const meta = EV_ICONS[ev.evidence_type] ?? { icon: '•', color: 'border-muted' }

  return (
    <div className="relative pl-10">
      {/* Timeline dot */}
      <div className={`absolute left-0 top-2 w-7 h-7 rounded-full bg-surface border-2 ${meta.color} flex items-center justify-center text-sm`}>
        {meta.icon}
      </div>
      {/* Card */}
      <div className="bg-surface border border-border rounded-lg p-4 mb-4">
        <div className="flex items-start justify-between gap-3 mb-2">
          <div>
            <p className="text-white text-sm font-medium">{ev.evidence_type.replace(/_/g, ' ')}</p>
            <p className="text-muted text-xs mt-0.5">{formatDateTime(ev.collected_at)}</p>
          </div>
          <div className="flex items-center gap-2 shrink-0">
            {verify && <VerifyBadge valid={verify.is_valid} />}
            <button
              onClick={() => setExpanded(!expanded)}
              className="text-muted hover:text-white text-xs px-2 py-1 bg-bg border border-border rounded"
            >
              {expanded ? '▲ hide' : '▼ details'}
            </button>
          </div>
        </div>

        {verify && !verify.is_valid && (
          <div className="bg-danger/10 border border-danger/30 rounded px-3 py-2 text-xs text-danger mb-2">
            ⚠️ Hash mismatch — this evidence record may have been tampered with
          </div>
        )}

        {expanded && (
          <div className="mt-2 space-y-2">
            {verify && (
              <div className="text-xs space-y-1 bg-bg border border-border rounded p-2">
                <p className="text-muted">Stored hash:</p>
                <p className="font-mono text-accent break-all text-[10px]">{verify.stored_hash}</p>
                {!verify.is_valid && (
                  <>
                    <p className="text-muted mt-1">Computed hash:</p>
                    <p className="font-mono text-danger break-all text-[10px]">{verify.computed_hash}</p>
                  </>
                )}
              </div>
            )}
            <pre className="text-muted text-[10px] leading-relaxed overflow-x-auto bg-bg border border-border rounded p-2">
              {JSON.stringify(ev.evidence_data, null, 2)}
            </pre>
          </div>
        )}
      </div>
    </div>
  )
}

export default function EvidenceViewer() {
  const [alertId, setAlertId] = useState('')
  const [submitted, setSubmitted] = useState('')

  const { data: bundle, isLoading: bundleLoading, error: bundleError, refetch: bundleRefetch } = useQuery({
    queryKey: ['evidence', submitted],
    queryFn: () => api.evidence(submitted),
    enabled: !!submitted,
  })

  const { data: verifyData } = useQuery({
    queryKey: ['verify', submitted],
    queryFn: () => api.verifyEvidence(submitted),
    enabled: !!submitted,
  })

  const verifyMap = Object.fromEntries((verifyData ?? []).map(v => [v.evidence_id, v]))

  function handleExport() {
    if (!bundle) return
    const blob = new Blob([JSON.stringify(bundle, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `evidence_${submitted.slice(0, 8)}.json`
    a.click()
    URL.revokeObjectURL(url)
  }

  const allValid = verifyData?.every(v => v.is_valid)

  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="text-xl font-semibold text-white">Evidence Viewer</h1>
        <p className="text-muted text-sm mt-0.5">Cryptographic audit trail for any alert · tamper detection included</p>
      </div>

      {/* Search */}
      <div className="flex gap-3">
        <input
          type="text"
          value={alertId}
          onChange={e => setAlertId(e.target.value)}
          placeholder="Paste alert UUID…"
          className="flex-1 bg-surface border border-border text-white placeholder-muted rounded-md px-4 py-2.5 text-sm font-mono focus:outline-none focus:border-accent"
          onKeyDown={e => e.key === 'Enter' && alertId.trim() && setSubmitted(alertId.trim())}
        />
        <button
          onClick={() => alertId.trim() && setSubmitted(alertId.trim())}
          className="px-4 py-2.5 bg-accent text-bg rounded-md text-sm font-medium hover:bg-accent/90 transition-colors"
        >
          Load
        </button>
      </div>

      {submitted && (
        <>
          {bundleError ? (
            <ErrorState message={String(bundleError)} onRetry={bundleRefetch} />
          ) : bundleLoading ? (
            <div className="space-y-4">
              {Array.from({ length: 4 }).map((_, i) => (
                <div key={i} className="pl-10">
                  <div className="skeleton h-20 rounded-lg" />
                </div>
              ))}
            </div>
          ) : bundle ? (
            <div className="space-y-4">
              {/* Summary header */}
              <div className="flex items-center justify-between bg-surface border border-border rounded-lg px-5 py-4">
                <div>
                  <p className="text-white font-medium text-sm">Alert {submitted.slice(0, 16)}…</p>
                  <div className="flex items-center gap-3 mt-1">
                    <span className="text-muted text-xs">Risk: <span className="text-white">{bundle.risk_score}</span></span>
                    <span className="text-muted text-xs">Status: <span className="text-white">{bundle.status}</span></span>
                    <span className="text-muted text-xs">Steps: <span className="text-white">{bundle.evidence_trail.length}</span></span>
                  </div>
                </div>
                <div className="flex items-center gap-3">
                  {verifyData && (
                    allValid
                      ? <span className="px-3 py-1 bg-success/20 text-success border border-success/30 rounded text-xs font-medium">✓ Chain Intact</span>
                      : <span className="px-3 py-1 bg-danger/20 text-danger border border-danger/30 rounded text-xs font-medium">⚠ Integrity Issue</span>
                  )}
                  <button
                    onClick={handleExport}
                    className="px-3 py-1.5 bg-accent/10 text-accent border border-accent/30 rounded text-xs hover:bg-accent/20 transition-colors"
                  >
                    Export JSON
                  </button>
                </div>
              </div>

              {/* Timeline */}
              <div className="relative before:absolute before:left-3 before:top-0 before:bottom-0 before:w-0.5 before:bg-border">
                {bundle.evidence_trail.map(ev => (
                  <EvidenceStep key={ev.id} ev={ev} verify={verifyMap[ev.id]} />
                ))}
              </div>
            </div>
          ) : null}
        </>
      )}

      {!submitted && (
        <div className="text-center py-20 text-muted">
          <p className="text-5xl mb-4">🔒</p>
          <p className="text-white font-medium">Enter an alert ID to view its evidence chain</p>
          <p className="text-sm mt-1">Every decision TrustSOC makes is recorded with a SHA-256 hash</p>
        </div>
      )}
    </div>
  )
}
