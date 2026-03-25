export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'

export type Finding = {
  id: string
  title: string
  severity: Severity
  status: 'open' | 'confirmed' | 'false-positive' | 'fixed'
  route: string
  description: string
}

export type ScanSummary = {
  id: string
  target: string
  status: 'queued' | 'running' | 'done' | 'failed'
  startedAt: string
  findings: Finding[]
}

export type DashboardMetric = {
  label: string
  value: string
  delta?: string
}
