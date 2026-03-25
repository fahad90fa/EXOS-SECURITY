import React from 'react'
import { Card } from '../../components/ui/Card'

const projects = [
  { name: 'Acme storefront', scope: 'app.acme.test', owner: 'Blue Team' },
  { name: 'Admin portal', scope: 'admin.acme.test', owner: 'AppSec' },
]

export default function ProjectsPage() {
  return (
    <div className="grid" style={{ gap: '1.25rem' }}>
      <header className="stack-sm">
        <p className="eyebrow">Projects</p>
        <h2>Scope and ownership</h2>
      </header>
      <div className="grid metrics-grid">
        {projects.map((project) => (
          <Card key={project.name}>
            <div className="stack-sm">
              <strong>{project.name}</strong>
              <p className="muted">Scope: {project.scope}</p>
              <p className="muted">Owner: {project.owner}</p>
            </div>
          </Card>
        ))}
      </div>
    </div>
  )
}
