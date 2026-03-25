import React from 'react'
import { ReportCard } from '../../components/reports/ReportCard'
import { Card } from '../../components/ui/Card'

export default function ReportsPage() {
  return (
    <div className="grid" style={{ gap: '1.25rem' }}>
      <header className="stack-sm">
        <p className="eyebrow">Reports</p>
        <h2>Export-ready summaries</h2>
      </header>
      <div className="grid" style={{ gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
        <ReportCard />
        <Card>
          <p className="eyebrow">Exports</p>
          <h3>Available formats</h3>
          <ul>
            <li>PDF</li>
            <li>HTML</li>
            <li>SARIF</li>
            <li>JSON</li>
          </ul>
        </Card>
      </div>
    </div>
  )
}
