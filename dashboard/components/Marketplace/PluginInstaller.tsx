import React from 'react'

export function PluginInstaller({ onInstall }: { onInstall?: () => void }) {
  return (
    <section className="panel">
      <h3>Plugin Installer</h3>
      <p>Installs the selected plugin after signature verification.</p>
      <button className="button" onClick={onInstall}>Install</button>
    </section>
  )
}
