<template>
  <section class="panel">
    <header class="panel-head">
      <div>
        <h3>Code Editor</h3>
        <p>Lightweight editor with line numbers and live word count.</p>
      </div>
      <span class="badge">{{ lineCount }} lines</span>
    </header>

    <div class="editor-shell">
      <pre class="gutter">{{ gutter }}</pre>
      <textarea
        class="editor"
        :value="modelValue"
        spellcheck="false"
        @input="$emit('update:modelValue', $event.target.value)"
      ></textarea>
    </div>
  </section>
</template>

<script>
export default {
  name: 'CodeEditor',
  props: { modelValue: { type: String, default: '' } },
  emits: ['update:modelValue'],
  computed: {
    lineCount() {
      return Math.max(String(this.modelValue || '').split('\n').length, 1)
    },
    gutter() {
      return Array.from({ length: this.lineCount }, (_, index) => String(index + 1).padStart(2, '0')).join('\n')
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

.editor-shell {
  display: grid;
  grid-template-columns: auto 1fr;
  border: 1px solid rgba(148, 163, 184, 0.22);
  border-radius: 1rem;
  overflow: hidden;
  background: rgba(15, 23, 42, 0.65);
}

.gutter {
  margin: 0;
  padding: 0.85rem 0.75rem;
  color: #64748b;
  background: rgba(15, 23, 42, 0.92);
  border-right: 1px solid rgba(148, 163, 184, 0.16);
  text-align: right;
  user-select: none;
}

.editor {
  min-height: 240px;
  border: 0;
  outline: none;
  resize: vertical;
  background: transparent;
  color: #e2e8f0;
  padding: 0.85rem 1rem;
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  line-height: 1.5;
}
</style>
