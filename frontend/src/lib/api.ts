import { API_URL, API_KEY } from '../config'

async function apiFetch<T>(path: string, options: RequestInit = {}): Promise<T> {
  const res = await fetch(`${API_URL}${path}`, {
    ...options,
    headers: {
      'x-api-key': API_KEY,
      'Content-Type': 'application/json',
      ...options.headers,
    },
  })
  if (!res.ok) {
    const text = await res.text()
    throw new Error(`API ${res.status}: ${text}`)
  }
  return res.json()
}

// ── Types ────────────────────────────────────────────────────────────────────

export interface Stats {
  total_alerts: number
  alerts_24h: number
  total_incidents: number
  incidents_24h: number
  high_risk_open: number
}

export interface Alert {
  id: string
  external_id?: string
  source_system: string
  risk_score: number
  confidence_score: number
  status: string
  incident_id?: string
  created_at: string
  normalized_alert?: {
    title?: string
    severity?: string
    source_host?: string
    source_ip?: string
    user?: string
    iocs?: Record<string, string[]>
  }
}

export interface EvidenceRecord {
  id: string
  evidence_type: string
  evidence_data: Record<string, unknown>
  source?: string
  collected_at: string
}

export interface EvidenceBundle {
  alert_id: string
  risk_score: number
  status: string
  evidence_trail: EvidenceRecord[]
  enrichments: unknown[]
  actions_taken: unknown[]
  policy_decisions: unknown[]
}

export interface EvidenceVerify {
  evidence_id: string
  is_valid: boolean
  stored_hash: string
  computed_hash: string
  message: string
}

export interface Incident {
  id: string
  title: string
  description?: string
  pattern_type: string
  severity: string
  status: string
  mitre_tactics: string[]
  mitre_techniques: string[]
  created_at: string
  alerts?: Alert[]
}

export interface MitreCoverage {
  techniques: Array<{
    techniqueID: string
    score: number
    tactic?: string
  }>
}

export interface MitreSummary {
  tactics: Array<{
    tactic: string
    technique_count: number
    incident_count: number
    techniques: Array<{ id: string; name: string; count: number }>
  }>
}

// ── API calls ────────────────────────────────────────────────────────────────

export const api = {
  stats: () => apiFetch<Stats>('/api/v1/stats'),

  alerts: (params?: { limit?: number; min_risk_score?: number; alert_status?: string }) => {
    const q = new URLSearchParams()
    if (params?.limit) q.set('limit', String(params.limit))
    if (params?.min_risk_score != null) q.set('min_risk_score', String(params.min_risk_score))
    if (params?.alert_status) q.set('alert_status', params.alert_status)
    return apiFetch<Alert[]>(`/api/v1/alerts?${q}`)
  },

  alert: (id: string) => apiFetch<Alert>(`/api/v1/alerts/${id}`),

  evidence: (id: string) => apiFetch<EvidenceBundle>(`/api/v1/alerts/${id}/evidence`),

  verifyEvidence: (id: string) => apiFetch<EvidenceVerify[]>(`/api/v1/alerts/${id}/evidence/verify`),

  incidents: () => apiFetch<Incident[]>('/api/v1/incidents'),

  incident: (id: string) => apiFetch<Incident>(`/api/v1/incidents/${id}`),

  mitreCoverage: () => apiFetch<MitreCoverage>('/api/v1/mitre/coverage'),

  mitreSummary: () => apiFetch<MitreSummary>('/api/v1/mitre/summary'),

  submitFeedback: (alertId: string, body: { feedback_type: string; notes?: string; analyst_id?: string }) =>
    apiFetch(`/api/v1/alerts/${alertId}/feedback`, { method: 'POST', body: JSON.stringify(body) }),
}
