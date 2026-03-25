'use client'

import React, { useState } from 'react'

export function PluginDeveloper({ onUpload }: { onUpload?: () => void }) {
  const [name, setName] = useState('')
  const [manifest, setManifest] = useState('')
  return (
    <section className="panel">
      <h3>Plugin Developer</h3>
      <p>Package a plugin, validate its manifest, and submit it to the marketplace.</p>
      <div className="stack">
        <input className="input" value={name} onChange={(event) => setName(event.target.value)} placeholder="Plugin name" />
        <textarea
          className="input"
          value={manifest}
          onChange={(event) => setManifest(event.target.value)}
          placeholder="Plugin manifest JSON"
          rows={6}
        />
      </div>
      <button className="button" onClick={onUpload}>Upload Plugin</button>
    </section>
  )
}
