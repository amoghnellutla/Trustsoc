import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { api } from '../lib/api'
import ErrorState from '../components/ErrorState'

// ATT&CK Tactic order
const TACTICS = [
  'Reconnaissance', 'Resource Development', 'Initial Access', 'Execution',
  'Persistence', 'Privilege Escalation', 'Defense Evasion', 'Credential Access',
  'Discovery', 'Lateral Movement', 'Collection', 'Command and Control',
  'Exfiltration', 'Impact',
]

function scoreColor(score: number): string {
  if (score === 0) return 'bg-border/60 text-muted hover:bg-border'
  if (score <= 2)  return 'bg-warning/30 text-warning hover:bg-warning/50 border border-warning/40'
  if (score <= 5)  return 'bg-orange-500/30 text-orange-300 hover:bg-orange-500/50 border border-orange-500/40'
  return 'bg-danger/40 text-danger hover:bg-danger/60 border border-danger/40'
}

interface TechCell {
  id: string
  score: number
  tactic?: string
}

export default function MitreHeatmap() {
  const [hovered, setHovered] = useState<TechCell | null>(null)

  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ['mitre-coverage'],
    queryFn: api.mitreCoverage,
  })

  const { data: summary } = useQuery({
    queryKey: ['mitre-summary'],
    queryFn: api.mitreSummary,
  })

  if (error) return <div className="p-6"><ErrorState message={String(error)} onRetry={refetch} /></div>

  // Build technique map by tactic
  const techsByTactic: Record<string, TechCell[]> = {}
  TACTICS.forEach(t => { techsByTactic[t] = [] })

  ;(data?.techniques ?? []).forEach(tech => {
    const tactic = tech.tactic ?? 'Unknown'
    if (!techsByTactic[tactic]) techsByTactic[tactic] = []
    techsByTactic[tactic].push({ id: tech.techniqueID, score: tech.score, tactic })
  })

  const activeTactics = TACTICS.filter(t => techsByTactic[t]?.length > 0)
  const totalTechniques = (data?.techniques ?? []).length
  const detectedTechniques = (data?.techniques ?? []).filter(t => t.score > 0).length

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-xl font-semibold text-white">MITRE ATT&CK Coverage</h1>
          <p className="text-muted text-sm mt-0.5">Detected techniques mapped to ATT&CK framework</p>
        </div>
        <div className="text-right text-sm">
          <p className="text-white font-semibold">{detectedTechniques} <span className="text-muted font-normal">/ {totalTechniques}</span></p>
          <p className="text-muted text-xs">techniques detected</p>
        </div>
      </div>

      {/* Legend */}
      <div className="flex items-center gap-4 text-xs text-muted">
        <span className="font-medium text-white">Coverage:</span>
        {[['Not seen', 'bg-border/60'], ['1–2 incidents', 'bg-warning/30'], ['3–5 incidents', 'bg-orange-500/30'], ['6+ incidents', 'bg-danger/40']].map(([label, cls]) => (
          <div key={label} className="flex items-center gap-1.5">
            <div className={`w-3 h-3 rounded-sm ${cls}`} />
            <span>{label}</span>
          </div>
        ))}
      </div>

      {/* Heatmap grid */}
      {isLoading ? (
        <div className="grid grid-cols-4 gap-3">
          {Array.from({ length: 8 }).map((_, i) => (
            <div key={i} className="space-y-2">
              <div className="skeleton h-5 w-24 rounded" />
              {Array.from({ length: 4 }).map((_, j) => <div key={j} className="skeleton h-8 rounded" />)}
            </div>
          ))}
        </div>
      ) : activeTactics.length === 0 ? (
        <div className="text-center py-16 text-muted">
          <p className="text-4xl mb-3">🗺️</p>
          <p className="text-white font-medium">No MITRE data yet</p>
          <p className="text-sm mt-1">Send alerts and create incidents to populate the heatmap</p>
        </div>
      ) : (
        <div className="overflow-x-auto">
          <div className="flex gap-3 min-w-max pb-2">
            {activeTactics.map(tactic => (
              <div key={tactic} className="w-36 shrink-0">
                <div className="text-[10px] font-semibold text-muted uppercase tracking-wide mb-2 truncate" title={tactic}>
                  {tactic}
                </div>
                <div className="space-y-1">
                  {techsByTactic[tactic].map(tech => (
                    <button
                      key={tech.id}
                      onMouseEnter={() => setHovered(tech)}
                      onMouseLeave={() => setHovered(null)}
                      className={`w-full px-2 py-1.5 rounded text-[11px] font-mono text-left transition-colors ${scoreColor(tech.score)}`}
                    >
                      {tech.id}
                      {tech.score > 0 && (
                        <span className="float-right font-sans font-bold">{tech.score}</span>
                      )}
                    </button>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Hover tooltip */}
      {hovered && hovered.score > 0 && (
        <div className="fixed bottom-6 right-6 bg-surface border border-accent/40 rounded-lg px-4 py-3 shadow-xl text-sm z-50 pointer-events-none">
          <p className="text-accent font-mono font-semibold">{hovered.id}</p>
          <p className="text-white mt-0.5">{hovered.tactic}</p>
          <p className="text-muted text-xs mt-1">{hovered.score} incident{hovered.score !== 1 ? 's' : ''} detected</p>
        </div>
      )}

      {/* Tactic summary table */}
      {summary?.tactics && summary.tactics.length > 0 && (
        <div className="bg-surface border border-border rounded-lg overflow-hidden">
          <div className="px-5 py-3 border-b border-border">
            <h2 className="text-sm font-semibold text-white">Coverage Summary by Tactic</h2>
          </div>
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border">
                {['Tactic', 'Techniques Detected', 'Total Incidents'].map(h => (
                  <th key={h} className="px-4 py-2 text-left text-xs font-medium text-muted">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {summary.tactics.map(t => (
                <tr key={t.tactic} className="border-b border-border/50">
                  <td className="px-4 py-2.5 text-white">{t.tactic}</td>
                  <td className="px-4 py-2.5 text-muted">{t.technique_count}</td>
                  <td className="px-4 py-2.5 text-muted">{t.incident_count}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
