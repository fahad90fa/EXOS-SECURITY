<template>
  <section class="panel">
    <header class="panel-head">
      <div>
        <h3>Network Topology</h3>
        <p>Shows services, trust boundaries, and lateral movement paths.</p>
      </div>
      <span class="badge">{{ services.length }} services</span>
    </header>

    <div class="topology">
      <article
        v-for="service in normalizedServices"
        :key="service.id"
        class="service-card"
        :class="{ compromised: service.status === 'compromised' }"
      >
        <div class="service-dot" :style="{ background: service.color }"></div>
        <div class="service-content">
          <strong>{{ service.name }}</strong>
          <span>{{ service.role }}</span>
        </div>
      </article>
    </div>
  </section>
</template>

<script>
export default {
  name: 'NetworkTopology',
  props: { services: { type: Array, default: () => [] } },
  computed: {
    normalizedServices() {
      const palette = ['#38bdf8', '#4ade80', '#facc15', '#f97316', '#fb7185']
      return this.services.map((service, index) => ({
        id: service.id || `service-${index}`,
        name: service.name || service.label || `Service ${index + 1}`,
        role: service.role || service.type || 'application',
        status: service.status || 'healthy',
        color: service.status === 'compromised' ? '#fb7185' : palette[index % palette.length],
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

.topology {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: 0.75rem;
}

.service-card {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  border-radius: 1rem;
  border: 1px solid rgba(148, 163, 184, 0.22);
  background: rgba(15, 23, 42, 0.62);
  padding: 0.9rem;
}

.service-card.compromised {
  border-color: rgba(251, 113, 133, 0.45);
  background: rgba(127, 29, 29, 0.26);
}

.service-dot {
  width: 0.9rem;
  height: 0.9rem;
  border-radius: 999px;
  flex: 0 0 auto;
}

.service-content {
  display: grid;
  gap: 0.15rem;
}

.service-content strong {
  color: #f8fafc;
}

.service-content span {
  color: #94a3b8;
  font-size: 0.88rem;
}
</style>
