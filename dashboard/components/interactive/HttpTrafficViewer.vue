<template>
  <section class="panel">
    <header class="panel-head">
      <div>
        <h3>HTTP Traffic Viewer</h3>
        <p>Inspect the request/response pair with basic parsing.</p>
      </div>
      <span class="badge">{{ requestLines.length + responseLines.length }} lines</span>
    </header>

    <div class="traffic-grid">
      <article class="traffic-card">
        <h4>Request</h4>
        <pre>{{ request || 'No request captured yet' }}</pre>
      </article>
      <article class="traffic-card">
        <h4>Response</h4>
        <pre>{{ response || 'No response captured yet' }}</pre>
      </article>
    </div>
  </section>
</template>

<script>
export default {
  name: 'HttpTrafficViewer',
  props: {
    request: { type: String, default: '' },
    response: { type: String, default: '' },
  },
  computed: {
    requestLines() {
      return String(this.request || '').split('\n').filter(Boolean)
    },
    responseLines() {
      return String(this.response || '').split('\n').filter(Boolean)
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

.traffic-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
  gap: 0.75rem;
}

.traffic-card {
  border: 1px solid rgba(148, 163, 184, 0.2);
  background: rgba(15, 23, 42, 0.58);
  border-radius: 1rem;
  padding: 0.9rem;
}

.traffic-card h4 {
  margin: 0 0 0.65rem;
  color: #f8fafc;
}

.traffic-card pre {
  margin: 0;
  white-space: pre-wrap;
  word-break: break-word;
  color: #cbd5e1;
  font-size: 0.88rem;
}
</style>
