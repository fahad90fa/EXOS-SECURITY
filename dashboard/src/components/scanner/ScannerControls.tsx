'use client'

import React, { useState } from 'react'
import { Button } from '../ui/Button'

export function ScannerControls() {
  const [target, setTarget] = useState('https://example.com')
  const [depth, setDepth] = useState(2)

  return (
    <section className="card stack">
      <div>
        <p className="eyebrow">Scanner</p>
        <h3>Start a new scan</h3>
      </div>
      <label className="field">
        Target URL
        <input value={target} onChange={(event) => setTarget(event.target.value)} />
      </label>
      <label className="field">
        Crawl depth
        <input type="range" min={1} max={5} value={depth} onChange={(event) => setDepth(Number(event.target.value))} />
        <span>{depth}</span>
      </label>
      <Button type="button" onClick={() => alert(`Queued scan for ${target} at depth ${depth}`)}>
        Queue scan
      </Button>
    </section>
  )
}
