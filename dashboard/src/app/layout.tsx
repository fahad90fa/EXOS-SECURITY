import React, { PropsWithChildren } from 'react'
import './globals.css'

export default function RootLayout({ children }: PropsWithChildren) {
  return (
    <html lang="en">
      <body>
        <div className="shell">
          <aside className="sidebar">
            <div className="stack">
              <div>
                <p className="eyebrow">Nexus Sentinel</p>
                <h1>Dashboard</h1>
                <p className="muted">Security operations, scan triage, and reporting in one view.</p>
              </div>
              <nav className="stack-sm">
                <a href="/">Overview</a>
                <a href="/scans">Scans</a>
                <a href="/projects">Projects</a>
                <a href="/reports">Reports</a>
                <a href="/settings">Settings</a>
              </nav>
            </div>
          </aside>
          <main className="content">{children}</main>
        </div>
      </body>
    </html>
  )
}
