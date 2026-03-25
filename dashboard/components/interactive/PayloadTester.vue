<template>
  <section class="panel">
    <header class="panel-head">
      <div>
        <h3>Payload Tester</h3>
        <p>Generate a payload variant and emit it for downstream testing.</p>
      </div>
      <span class="badge">{{ payload.length }} chars</span>
    </header>

    <div class="controls">
      <input v-model="payload" class="input" type="text" placeholder="Enter payload" />
      <select v-model="mode" class="select">
        <option value="raw">Raw</option>
        <option value="url">URL encoded</option>
        <option value="base64">Base64</option>
        <option value="upper">Uppercase</option>
      </select>
      <button class="primary" type="button" @click="emitPayload">Run</button>
    </div>

    <div class="preview">
      <span class="preview-label">Preview</span>
      <pre>{{ preview }}</pre>
    </div>
  </section>
</template>

<script>
export default {
  name: 'PayloadTester',
  emits: ['submit'],
  data() {
    return {
      payload: '',
      mode: 'raw',
    }
  },
  computed: {
    preview() {
      if (this.mode === 'url') {
        return encodeURIComponent(this.payload)
      }
      if (this.mode === 'base64') {
        return typeof window !== 'undefined' ? window.btoa(unescape(encodeURIComponent(this.payload))) : this.payload
      }
      if (this.mode === 'upper') {
        return this.payload.toUpperCase()
      }
      return this.payload
    },
  },
  methods: {
    emitPayload() {
      this.$emit('submit', this.preview)
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

.controls {
  display: grid;
  grid-template-columns: 1fr 140px auto;
  gap: 0.75rem;
}

.input,
.select {
  width: 100%;
  border-radius: 0.85rem;
  border: 1px solid rgba(148, 163, 184, 0.24);
  background: rgba(15, 23, 42, 0.65);
  color: #e2e8f0;
  padding: 0.75rem 0.9rem;
}

.primary {
  border-radius: 0.85rem;
  background: linear-gradient(135deg, #06b6d4, #2563eb);
  color: white;
  border: 0;
  padding: 0.75rem 1rem;
  font-weight: 600;
}

.preview {
  border: 1px solid rgba(148, 163, 184, 0.2);
  background: rgba(15, 23, 42, 0.58);
  border-radius: 1rem;
  padding: 0.9rem;
}

.preview-label {
  display: inline-block;
  margin-bottom: 0.5rem;
  color: #94a3b8;
  font-size: 0.8rem;
  text-transform: uppercase;
  letter-spacing: 0.12em;
}

.preview pre {
  margin: 0;
  color: #e2e8f0;
  white-space: pre-wrap;
  word-break: break-word;
}

@media (max-width: 720px) {
  .controls {
    grid-template-columns: 1fr;
  }
}
</style>
