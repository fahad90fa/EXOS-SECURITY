import React from 'react'
import { OverviewPanel } from '../components/dashboard/OverviewPanel'
import { ScannerControls } from '../components/scanner/ScannerControls'
import { TrafficTable } from '../components/proxy/TrafficTable'
import { ReportCard } from '../components/reports/ReportCard'
import { Card } from '../components/ui/Card'
import { scans } from '../lib/mock-data'
import { formatTimestamp } from '../lib/format'

export default function Page() {
  return (
    <div className="grid" style={{ gap: '1.25rem' }}>
      <header className="stack-sm">
        <p className="eyebrow">Overview</p>
        <h2>Live security workspace</h2>
        <p className="muted">A compact landing page for the dashboard shell and its core panels.</p>
      </header>

      <OverviewPanel />

      <div className="grid" style={{ gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
        <ScannerControls />
        <Card>
          <p className="eyebrow">Scans</p>
          <h3>Recent activity</h3>
          <div className="stack">
            {scans.map((scan) => (
              <article key={scan.id} className="stack-sm">
                <strong>{scan.target}</strong>
                <p className="muted">
                  {scan.status} · {formatTimestamp(scan.startedAt)} · {scan.findings.length} findings
                </p>
              </article>
            ))}
          </div>
        </Card>
      </div>

      <div className="grid" style={{ gridTemplateColumns: '1.1fr 0.9fr', gap: '1rem' }}>
        <TrafficTable />
        <ReportCard />
      </div>
    </div>
  )
}
