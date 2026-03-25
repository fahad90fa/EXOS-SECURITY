<template>
  <section class="panel">
    <header class="panel-head">
      <div>
        <h3>Compliance Radar</h3>
        <p>Highlights control coverage across key frameworks.</p>
      </div>
      <span class="badge">{{ averageScore }}%</span>
    </header>

    <svg class="viz" viewBox="0 0 420 420" role="img" aria-label="Compliance radar chart">
      <g v-for="ring in rings" :key="ring" class="grid-ring">
        <circle cx="210" cy="210" :r="ring" fill="none" stroke="rgba(148,163,184,0.18)" />
      </g>
      <g>
        <line
          v-for="axis in renderedScores"
          :key="axis.label"
          x1="210"
          y1="210"
          :x2="axis.x"
          :y2="axis.y"
          stroke="rgba(148,163,184,0.28)"
        />
      </g>
      <polygon :points="polygonPoints" fill="rgba(34, 211, 238, 0.22)" stroke="#22d3ee" stroke-width="2" />
      <g v-for="axis in renderedScores" :key="axis.label + '-label'">
        <circle :cx="axis.x" :cy="axis.y" r="4" fill="#22d3ee" />
        <text :x="axis.labelX" :y="axis.labelY" class="label" :text-anchor="axis.textAnchor">{{ axis.label }} {{ axis.score }}%</text>
      </g>
    </svg>

    <ul class="score-list">
      <li v-for="item in renderedScores" :key="item.label">
        <span>{{ item.label }}</span>
        <strong>{{ item.score }}%</strong>
      </li>
    </ul>
  </section>
</template>

<script>
export default {
  name: 'ComplianceRadar',
  props: { scores: { type: Array, default: () => [] } },
  computed: {
    renderedScores() {
      const normalized = this.scores.map((item, index) => ({
        label: item.label || `Axis ${index + 1}`,
        score: Math.max(0, Math.min(100, Number(item.score ?? 0))),
      }))
      const count = Math.max(normalized.length, 1)
      return normalized.map((item, index) => {
        const angle = (-Math.PI / 2) + (Math.PI * 2 * index) / count
        const radius = 120 * (item.score / 100)
        const x = 210 + Math.cos(angle) * radius
        const y = 210 + Math.sin(angle) * radius
        const labelRadius = 162
        return {
          ...item,
          x,
          y,
          labelX: 210 + Math.cos(angle) * labelRadius,
          labelY: 210 + Math.sin(angle) * labelRadius,
          textAnchor: Math.cos(angle) > 0.2 ? 'start' : Math.cos(angle) < -0.2 ? 'end' : 'middle',
        }
      })
    },
    polygonPoints() {
      return this.renderedScores.map((point) => `${point.x},${point.y}`).join(' ')
    },
    averageScore() {
      if (!this.renderedScores.length) {
        return 0
      }
      const total = this.renderedScores.reduce((sum, item) => sum + item.score, 0)
      return Math.round(total / this.renderedScores.length)
    },
    rings() {
      return [40, 80, 120, 160]
    },
  },
}
</script>

<style scoped>
.panel {
  display: grid;
  gap: 1rem;
}

.panel-head {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 0.75rem;
}

.badge {
  border-radius: 999px;
  padding: 0.35rem 0.75rem;
  background: rgba(15, 23, 42, 0.75);
  color: #e2e8f0;
  border: 1px solid rgba(148, 163, 184, 0.3);
}

.viz {
  width: 100%;
  max-width: 420px;
  margin: 0 auto;
}

.label {
  fill: #e2e8f0;
  font-size: 11px;
}

.score-list {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
  gap: 0.6rem;
  margin: 0;
  padding: 0;
  list-style: none;
}

.score-list li {
  display: flex;
  justify-content: space-between;
  gap: 0.75rem;
  border: 1px solid rgba(148, 163, 184, 0.2);
  background: rgba(15, 23, 42, 0.56);
  border-radius: 0.9rem;
  padding: 0.7rem 0.85rem;
}

.score-list span,
.score-list strong {
  color: #e2e8f0;
}
</style>
