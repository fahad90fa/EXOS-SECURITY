import React from 'react'
import { scans } from '../../lib/mock-data'
import { Card } from '../../components/ui/Card'
import { formatTimestamp } from '../../lib/format'

export default function ScansPage() {
  return (
    <div className="grid" style={{ gap: '1.25rem' }}>
      <header className="stack-sm">
        <p className="eyebrow">Scans</p>
        <h2>Queued and completed jobs</h2>
      </header>
      {scans.map((scan) => (
        <Card key={scan.id}>
          <div className="stack-sm">
            <strong>{scan.target}</strong>
            <p className="muted">
              {scan.status} · {formatTimestamp(scan.startedAt)}
            </p>
            <p className="muted">{scan.findings.length} findings linked to this run.</p>
          </div>
        </Card>
      ))}
    </div>
  )
}
