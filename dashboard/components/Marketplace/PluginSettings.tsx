'use client'

import React, { useEffect, useState } from 'react'

export function PluginSettings({ settings = {} as Record<string, string> }) {
  const [values, setValues] = useState(settings)

  useEffect(() => {
    setValues(settings)
  }, [settings])

  return (
    <section className="panel">
      <h3>Plugin Settings</h3>
      <p>Configuration values are mapped from the plugin manifest.</p>
      {Object.entries(values).map(([key, value]) => (
        <div className="setting-row" key={key}>
          <label>{key}</label>
          <input
            value={value}
            onChange={(event) => setValues((current) => ({ ...current, [key]: event.target.value }))}
          />
        </div>
      ))}
    </section>
  )
}
