<template>
  <section class="panel attack-surface">
    <header class="panel-head">
      <div>
        <h3>Attack Surface Graph</h3>
        <p>{{ nodes.length }} nodes, {{ edges.length }} edges</p>
      </div>
      <button class="ghost" type="button" @click="resetFocus">Reset focus</button>
    </header>

    <svg class="viz" viewBox="0 0 720 420" role="img" aria-label="Attack surface graph">
      <defs>
        <linearGradient id="attack-surface-line" x1="0%" x2="100%" y1="0%" y2="0%">
          <stop offset="0%" stop-color="#22d3ee" stop-opacity="0.4" />
          <stop offset="100%" stop-color="#f97316" stop-opacity="0.9" />
        </linearGradient>
      </defs>

      <g>
        <line
          v-for="edge in renderedEdges"
          :key="edge.id"
          :x1="edge.source.x"
          :y1="edge.source.y"
          :x2="edge.target.x"
          :y2="edge.target.y"
          :stroke="edge.highlight ? 'url(#attack-surface-line)' : 'rgba(148, 163, 184, 0.32)'"
          :stroke-width="edge.highlight ? 3 : 1.5"
        />
      </g>

      <g>
        <g
          v-for="node in renderedNodes"
          :key="node.id"
          class="node"
          :class="{ active: node.id === activeNodeId }"
          :transform="`translate(${node.x}, ${node.y})`"
          @click="activeNodeId = node.id"
        >
          <circle :r="node.radius" :fill="node.fill" :stroke="node.stroke" />
          <text class="node-label" text-anchor="middle" :y="node.radius + 16">{{ node.label }}</text>
        </g>
      </g>
    </svg>

    <footer class="legend">
      <div v-for="item in severityLegend" :key="item.label" class="legend-item">
        <span class="swatch" :style="{ background: item.color }"></span>
        <span>{{ item.label }}</span>
      </div>
    </footer>
  </section>
</template>

<script>
export default {
  name: 'AttackSurfaceGraph',
  props: {
    nodes: { type: Array, default: () => [] },
    edges: { type: Array, default: () => [] },
  },
  data() {
    return {
      activeNodeId: null,
      severityLegend: [
        { label: 'Critical', color: '#fb7185' },
        { label: 'High', color: '#f97316' },
        { label: 'Medium', color: '#facc15' },
        { label: 'Low', color: '#38bdf8' },
      ],
    }
  },
  computed: {
    renderedNodes() {
      const radius = 130
      const centerX = 360
      const centerY = 210
      const count = Math.max(this.nodes.length, 1)
      return this.nodes.map((node, index) => {
        const angle = (Math.PI * 2 * index) / count - Math.PI / 2
        const severity = String(node.severity || node.risk || 'low').toLowerCase()
        const palette = {
          critical: ['#fb7185', '#7f1d1d'],
          high: ['#f97316', '#7c2d12'],
          medium: ['#facc15', '#713f12'],
          low: ['#38bdf8', '#0f172a'],
        }[severity] || ['#38bdf8', '#0f172a']
        return {
          id: node.id || node.label || `node-${index}`,
          label: node.label || node.name || `Node ${index + 1}`,
          x: centerX + Math.cos(angle) * radius,
          y: centerY + Math.sin(angle) * radius,
          radius: this.activeNodeId === (node.id || node.label || `node-${index}`) ? 20 : 16,
          fill: palette[0],
          stroke: palette[1],
        }
      })
    },
    renderedEdges() {
      return this.edges.map((edge, index) => {
        const source = this.renderedNodes.find((node) => node.id === (edge.source || edge.from)) || this.renderedNodes[index % this.renderedNodes.length] || { x: 160, y: 160 }
        const target = this.renderedNodes.find((node) => node.id === (edge.target || edge.to)) || this.renderedNodes[(index + 1) % this.renderedNodes.length] || { x: 560, y: 260 }
        return {
          id: edge.id || `${source.id || index}-${target.id || index}`,
          source,
          target,
          highlight: this.activeNodeId && (source.id === this.activeNodeId || target.id === this.activeNodeId),
        }
      })
    },
  },
  methods: {
    resetFocus() {
      this.activeNodeId = null
    },
  },
}
</script>

<style scoped>
.panel {
  display: grid;
  gap: 1rem;
}

.panel-head,
.legend {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 0.75rem;
}

.ghost {
  border: 1px solid rgba(148, 163, 184, 0.35);
  background: rgba(15, 23, 42, 0.75);
  color: #e2e8f0;
  border-radius: 999px;
  padding: 0.45rem 0.8rem;
}

.viz {
  width: 100%;
  min-height: 320px;
}

.node {
  cursor: pointer;
}

.node circle {
  transition: transform 180ms ease, filter 180ms ease;
}

.node.active circle,
.node:hover circle {
  filter: drop-shadow(0 0 10px rgba(34, 211, 238, 0.45));
}

.node-label {
  fill: #cbd5e1;
  font-size: 12px;
}

.legend {
  flex-wrap: wrap;
}

.legend-item {
  display: inline-flex;
  align-items: center;
  gap: 0.4rem;
  color: #cbd5e1;
  font-size: 0.85rem;
}

.swatch {
  width: 0.75rem;
  height: 0.75rem;
  border-radius: 999px;
}
</style>
