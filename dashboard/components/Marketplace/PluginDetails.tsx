import React from 'react'
import type { Plugin } from './PluginBrowser'

export function PluginDetails({ plugin }: { plugin?: Plugin }) {
  if (!plugin) return <section className="panel">Select a plugin to inspect its manifest, trust level, and install options.</section>
  return (
    <section className="panel">
      <div className="panel-head">
        <h3>{plugin.name}</h3>
        {plugin.verified ? <span className="verified">Verified</span> : null}
      </div>
      <p>{plugin.description}</p>
      <dl className="details">
        <div>
          <dt>Category</dt>
          <dd>{plugin.category}</dd>
        </div>
        <div>
          <dt>Rating</dt>
          <dd>{plugin.rating?.toFixed(1) ?? 'Unrated'}</dd>
        </div>
        <div>
          <dt>Downloads</dt>
          <dd>{plugin.downloads?.toLocaleString() ?? '0'}</dd>
        </div>
      </dl>
    </section>
  )
}
