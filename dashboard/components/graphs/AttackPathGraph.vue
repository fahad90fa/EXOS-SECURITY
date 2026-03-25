<template>
  <section class="panel">
    <header class="panel-head">
      <div>
        <h3>Attack Path Graph</h3>
        <p>Visualizes how access evolves from entry point to impact.</p>
      </div>
      <span class="badge">{{ paths.length }} paths</span>
    </header>

    <svg class="viz" viewBox="0 0 720 260" role="img" aria-label="Attack path graph">
      <g v-for="(path, index) in renderedPaths" :key="path.id">
        <circle :cx="path.x" :cy="path.y" r="14" :fill="path.color" />
        <line
          v-if="index < renderedPaths.length - 1"
          :x1="path.x + 14"
          :y1="path.y"
          :x2="renderedPaths[index + 1].x - 14"
          :y2="renderedPaths[index + 1].y"
          stroke="rgba(148,163,184,0.5)"
          stroke-width="2"
          stroke-dasharray="4 4"
        />
        <text :x="path.x" :y="path.y + 30" text-anchor="middle" class="label">{{ path.label }}</text>
      </g>
    </svg>

    <ol class="path-list">
      <li v-for="path in renderedPaths" :key="path.id">
        <strong>{{ path.label }}</strong>
        <span>{{ path.summary }}</span>
      </li>
    </ol>
  </section>
</template>

<script>
export default {
  name: 'AttackPathGraph',
  props: { paths: { type: Array, default: () => [] } },
  computed: {
    renderedPaths() {
      const palette = ['#38bdf8', '#f97316', '#facc15', '#fb7185', '#4ade80']
      return this.paths.map((path, index) => ({
        id: path.id || `path-${index}`,
        label: path.label || path.name || `Stage ${index + 1}`,
        summary: path.summary || path.description || 'Transition in the attack chain',
        x: 90 + index * 140,
        y: 120 + (index % 2 === 0 ? -28 : 28),
        color: palette[index % palette.length],
      }))
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

.label {
  fill: #e2e8f0;
  font-size: 12px;
}

.path-list {
  display: grid;
  gap: 0.65rem;
  margin: 0;
  padding-left: 1.1rem;
}

.path-list li {
  color: #cbd5e1;
}

.path-list span {
  display: block;
  color: #94a3b8;
  font-size: 0.88rem;
}
</style>
