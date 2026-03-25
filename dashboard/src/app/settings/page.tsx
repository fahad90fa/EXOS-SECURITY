import React from 'react'
import { Card } from '../../components/ui/Card'

export default function SettingsPage() {
  return (
    <div className="grid" style={{ gap: '1.25rem' }}>
      <header className="stack-sm">
        <p className="eyebrow">Settings</p>
        <h2>Workspace preferences</h2>
      </header>
      <Card>
        <div className="stack">
          <label className="field">
            Theme
            <input defaultValue="Dark nebula" />
          </label>
          <label className="field">
            Default target
            <input defaultValue="https://example.com" />
          </label>
        </div>
      </Card>
    </div>
  )
}
