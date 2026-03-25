'use client'

import React, { useMemo, useState } from 'react'

export type Plugin = {
  id: string
  name: string
  category: string
  description: string
  rating?: number
  downloads?: number
  verified?: boolean
}

export function PluginBrowser({ plugins = [] }: { plugins?: Plugin[] }) {
  const [query, setQuery] = useState('')
  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase()
    return plugins.filter((plugin) => {
      const haystack = `${plugin.name} ${plugin.category} ${plugin.description}`.toLowerCase()
      return !needle || haystack.includes(needle)
    })
  }, [plugins, query])

  return (
    <section className="panel">
      <div className="panel-head">
        <div>
          <h3>Plugin Browser</h3>
          <p>Browse community and official plugins with trust signals.</p>
        </div>
        <input
          className="input"
          value={query}
          onChange={(event) => setQuery(event.target.value)}
          placeholder="Search plugins"
        />
      </div>
      <div className="plugin-grid">
        {filtered.map((plugin) => (
          <article key={plugin.id} className="plugin-card">
            <div className="plugin-row">
              <strong>{plugin.name}</strong>
              {plugin.verified ? <span className="verified">Verified</span> : null}
            </div>
            <div className="meta">
              <span>{plugin.category}</span>
              <span>{plugin.rating?.toFixed(1) ?? '—'} stars</span>
              <span>{plugin.downloads?.toLocaleString() ?? '0'} downloads</span>
            </div>
            <p>{plugin.description}</p>
          </article>
        ))}
      </div>
    </section>
  )
}
