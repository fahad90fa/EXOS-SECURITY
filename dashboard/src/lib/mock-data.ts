import type { DashboardMetric, Finding, ScanSummary } from '../types'

export const metrics: DashboardMetric[] = [
  { label: 'Open findings', value: '18', delta: '+3 today' },
  { label: 'Critical issues', value: '2', delta: '-1 from last run' },
  { label: 'Targets scanned', value: '124', delta: '+9 this week' },
  { label: 'Avg. scan time', value: '8m 42s', delta: '-14%' },
]

export const findings: Finding[] = [
  {
    id: 'fnd-001',
    title: 'Reflected XSS in search endpoint',
    severity: 'high',
    status: 'confirmed',
    route: '/search?q=',
    description: 'User input is reflected into the response without output encoding.',
  },
  {
    id: 'fnd-002',
    title: 'SSRF via webhook import',
    severity: 'critical',
    status: 'open',
    route: '/api/webhooks/import',
    description: 'External URL fetches can reach internal services and metadata endpoints.',
  },
  {
    id: 'fnd-003',
    title: 'Missing security headers',
    severity: 'medium',
    status: 'fixed',
    route: '/',
    description: 'Several responses still omit CSP and frame-ancestors directives.',
  },
]

export const scans: ScanSummary[] = [
  {
    id: 'scan-001',
    target: 'https://example.com',
    status: 'done',
    startedAt: '2026-03-25T08:15:00Z',
    findings,
  },
  {
    id: 'scan-002',
    target: 'https://admin.example.com',
    status: 'running',
    startedAt: '2026-03-25T09:40:00Z',
    findings: findings.slice(0, 2),
  },
]
