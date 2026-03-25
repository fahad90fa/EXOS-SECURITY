<template>
  <section class="panel">
    <header class="panel-head">
      <div>
        <h3>Trend Analysis</h3>
        <p>Tracks vulnerability volume over time.</p>
      </div>
      <span class="badge">{{ points.length }} points</span>
    </header>

    <svg class="viz" viewBox="0 0 720 240" role="img" aria-label="Trend analysis chart">
      <line x1="40" y1="200" x2="680" y2="200" stroke="rgba(148,163,184,0.35)" />
      <polyline
        :points="linePoints"
        fill="none"
        stroke="#22d3ee"
        stroke-width="3"
        stroke-linejoin="round"
        stroke-linecap="round"
      />
      <circle v-for="point in renderedPoints" :key="point.label" :cx="point.x" :cy="point.y" r="5" fill="#22d3ee" />
    </svg>

    <div class="stats">
      <article v-for="point in renderedPoints" :key="point.label" class="stat">
        <span>{{ point.label }}</span>
        <strong>{{ point.value }}</strong>
      </article>
    </div>
  </section>
</template>

<script>
export default {
  name: 'TrendAnalysis',
  props: { points: { type: Array, default: () => [] } },
  computed: {
    renderedPoints() {
      const normalized = this.points.map((point, index) => ({
        label: point.label || `Point ${index + 1}`,
        value: Number(point.value ?? 0),
      }))
      const max = Math.max(...normalized.map((point) => point.value), 1)
      const span = Math.max(normalized.length - 1, 1)
      return normalized.map((point, index) => ({
        ...point,
        x: 40 + (640 * index) / span,
        y: 200 - (140 * point.value) / max,
      }))
    },
    linePoints() {
      return this.renderedPoints.map((point) => `${point.x},${point.y}`).join(' ')
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
  min-height: 220px;
}

.stats {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(100px, 1fr));
  gap: 0.75rem;
}

.stat {
  border: 1px solid rgba(148, 163, 184, 0.2);
  background: rgba(15, 23, 42, 0.56);
  border-radius: 0.9rem;
  padding: 0.75rem;
  display: grid;
  gap: 0.25rem;
}

.stat span {
  color: #94a3b8;
  font-size: 0.8rem;
}

.stat strong {
  color: #f8fafc;
}
</style>
