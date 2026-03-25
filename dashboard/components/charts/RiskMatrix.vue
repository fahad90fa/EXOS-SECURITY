<template>
  <section class="panel">
    <header class="panel-head">
      <div>
        <h3>Risk Matrix</h3>
        <p>Maps likelihood against impact for triage prioritization.</p>
      </div>
      <span class="badge">{{ items.length }} items</span>
    </header>

    <div class="matrix">
      <div v-for="row in grid" :key="row.key" class="row">
        <div v-for="cell in row.cells" :key="cell.key" class="cell" :class="cell.level">
          <span v-if="cell.item" class="cell-item">
            <strong>{{ cell.item.title }}</strong>
            <small>{{ cell.item.risk }}</small>
          </span>
        </div>
      </div>
    </div>
  </section>
</template>

<script>
export default {
  name: 'RiskMatrix',
  props: { items: { type: Array, default: () => [] } },
  computed: {
    grid() {
      const rows = ['Low', 'Medium', 'High', 'Critical']
      const cols = ['Low', 'Medium', 'High', 'Critical']
      const normalized = this.items.map((item, index) => ({
        id: item.id || `risk-${index}`,
        title: item.title || item.name || `Finding ${index + 1}`,
        risk: item.risk || item.severity || 'Medium',
        row: item.row || rows[Math.min(index, rows.length - 1)],
        col: item.col || cols[Math.min((index * 2) % cols.length, cols.length - 1)],
      }))

      return rows.map((rowLabel, rowIndex) => ({
        key: rowLabel,
        cells: cols.map((colLabel, colIndex) => {
          const item = normalized.find((candidate) => candidate.row === rowLabel && candidate.col === colLabel)
          const level = ['low', 'medium', 'high', 'critical'][Math.max(rowIndex, colIndex)]
          return {
            key: `${rowLabel}-${colLabel}`,
            level,
            item,
          }
        }),
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

.matrix {
  display: grid;
  gap: 0.4rem;
}

.row {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 0.4rem;
}

.cell {
  min-height: 92px;
  border-radius: 0.9rem;
  border: 1px solid rgba(148, 163, 184, 0.2);
  background: rgba(15, 23, 42, 0.45);
  display: flex;
  align-items: flex-end;
  padding: 0.75rem;
}

.cell.low {
  background: rgba(56, 189, 248, 0.12);
}

.cell.medium {
  background: rgba(250, 204, 21, 0.14);
}

.cell.high {
  background: rgba(249, 115, 22, 0.16);
}

.cell.critical {
  background: rgba(251, 113, 133, 0.2);
}

.cell-item {
  display: grid;
  gap: 0.15rem;
}

.cell-item strong {
  color: #f8fafc;
}

.cell-item small {
  color: #cbd5e1;
}
</style>
