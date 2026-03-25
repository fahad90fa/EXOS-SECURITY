import React from 'react'
import { metrics } from '../../lib/mock-data'
import { Card } from '../ui/Card'

export function OverviewPanel() {
  return (
    <div className="grid metrics-grid">
      {metrics.map((metric) => (
        <Card key={metric.label}>
          <p className="eyebrow">{metric.label}</p>
          <h2 className="metric-value">{metric.value}</h2>
          <p className="muted">{metric.delta}</p>
        </Card>
      ))}
    </div>
  )
}
