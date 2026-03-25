import React from 'react'

type TrafficRow = {
  method: string
  path: string
  status: number
  size: string
}

const rows: TrafficRow[] = [
  { method: 'GET', path: '/api/v1/scans', status: 200, size: '2.1 KB' },
  { method: 'POST', path: '/api/v1/mobile/analyze', status: 201, size: '9.8 KB' },
  { method: 'GET', path: '/api/v1/reports/latest', status: 200, size: '3.4 KB' },
]

export function TrafficTable() {
  return (
    <section className="card">
      <div className="stack-sm">
        <p className="eyebrow">Proxy</p>
        <h3>Recent traffic</h3>
      </div>
      <div className="table">
        {rows.map((row) => (
          <div key={`${row.method}-${row.path}`} className="table-row">
            <span>{row.method}</span>
            <span>{row.path}</span>
            <span>{row.status}</span>
            <span>{row.size}</span>
          </div>
        ))}
      </div>
    </section>
  )
}
