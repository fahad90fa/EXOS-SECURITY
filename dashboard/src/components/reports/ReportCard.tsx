import React from 'react'
import { findings } from '../../lib/mock-data'
import { severityTone } from '../../lib/format'

export function ReportCard() {
  return (
    <section className="card">
      <div className="stack-sm">
        <p className="eyebrow">Reports</p>
        <h3>Latest findings</h3>
      </div>
      <div className="stack">
        {findings.map((finding) => (
          <article key={finding.id} className="finding-row">
            <div>
              <strong>{finding.title}</strong>
              <p className="muted">{finding.route}</p>
            </div>
            <span className={`pill ${severityTone(finding.severity)}`}>{finding.severity}</span>
          </article>
        ))}
      </div>
    </section>
  )
}
