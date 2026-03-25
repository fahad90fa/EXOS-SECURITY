<template>
  <section class="bg-gray-800 border border-gray-700 rounded-2xl p-5 space-y-4">
    <div class="flex items-start justify-between gap-4">
      <div>
        <h3 class="text-xl font-semibold text-white">APK Upload</h3>
        <p class="text-sm text-gray-400">
          Drop an APK here or pick a file to run MobileGuard static analysis.
        </p>
      </div>
      <span class="inline-flex items-center rounded-full border border-cyan-500/30 bg-cyan-500/10 px-3 py-1 text-xs text-cyan-300">
        API-backed
      </span>
    </div>

    <label
      class="group block cursor-pointer rounded-xl border-2 border-dashed border-gray-600 bg-gray-900/60 p-6 text-center transition hover:border-cyan-400 hover:bg-gray-900"
    >
      <input
        class="hidden"
        type="file"
        accept=".apk,application/vnd.android.package-archive"
        @change="onSelectFile"
      />
      <div class="space-y-2">
        <p class="text-base font-medium text-white">Choose an APK to analyze</p>
        <p class="text-sm text-gray-400">
          {{ selectedFileName || 'No file selected yet' }}
        </p>
      </div>
    </label>

    <div class="flex flex-wrap items-center gap-3">
      <button
        class="rounded-lg bg-cyan-600 px-4 py-2 text-sm font-semibold text-white transition hover:bg-cyan-500 disabled:cursor-not-allowed disabled:opacity-50"
        :disabled="!selectedFile || isAnalyzing"
        @click="analyze"
      >
        {{ isAnalyzing ? 'Analyzing...' : 'Run Analysis' }}
      </button>
      <button
        class="rounded-lg border border-gray-600 px-4 py-2 text-sm font-semibold text-gray-200 transition hover:border-gray-500 hover:bg-gray-700/60 disabled:cursor-not-allowed disabled:opacity-50"
        :disabled="!selectedFile || isAnalyzing"
        @click="clear"
      >
        Clear
      </button>
      <span v-if="error" class="text-sm text-rose-400">{{ error }}</span>
      <span v-else-if="isAnalyzing" class="text-sm text-gray-400">Uploading to {{ apiBaseUrl }}</span>
    </div>

    <div v-if="report" class="grid gap-4 md:grid-cols-3">
      <article class="rounded-xl border border-gray-700 bg-gray-900/80 p-4">
        <p class="text-xs uppercase tracking-[0.24em] text-gray-500">Package</p>
        <p class="mt-2 break-all text-sm text-white">{{ report.package_name || 'Unknown' }}</p>
      </article>
      <article class="rounded-xl border border-gray-700 bg-gray-900/80 p-4">
        <p class="text-xs uppercase tracking-[0.24em] text-gray-500">Risk</p>
        <p class="mt-2 text-sm text-white">{{ report.risk_score }} / 100</p>
      </article>
      <article class="rounded-xl border border-gray-700 bg-gray-900/80 p-4">
        <p class="text-xs uppercase tracking-[0.24em] text-gray-500">Findings</p>
        <p class="mt-2 text-sm text-white">{{ report.findings.length }}</p>
      </article>
    </div>

    <div v-if="report" class="space-y-3">
      <h4 class="text-sm font-semibold uppercase tracking-[0.24em] text-gray-400">Findings</h4>
      <div class="space-y-2">
        <article
          v-for="finding in report.findings"
          :key="finding.id"
          class="rounded-xl border border-gray-700 bg-gray-900/70 p-4"
        >
          <div class="flex flex-wrap items-center justify-between gap-2">
            <div>
              <p class="text-sm font-semibold text-white">{{ finding.title }}</p>
              <p class="text-xs text-gray-400">{{ finding.id }} · {{ finding.category }}</p>
            </div>
            <span class="rounded-full px-2 py-1 text-xs font-semibold" :class="severityClass(finding.severity)">
              {{ finding.severity }}
            </span>
          </div>
          <p class="mt-3 text-sm text-gray-300">{{ finding.description }}</p>
          <p class="mt-2 text-sm text-cyan-300">{{ finding.recommendation }}</p>
        </article>
      </div>
    </div>
  </section>
</template>

<script>
import { computed, ref } from 'vue'

const DEFAULT_API_BASE = 'http://127.0.0.1:3000'

export default {
  name: 'ApkUpload',
  setup() {
    const selectedFile = ref(null)
    const report = ref(null)
    const error = ref('')
    const isAnalyzing = ref(false)

    const apiBaseUrl = computed(() => {
      return import.meta.env.VITE_NEXUS_API_URL || DEFAULT_API_BASE
    })

    const selectedFileName = computed(() => selectedFile.value?.name || '')

    const onSelectFile = (event) => {
      const [file] = event.target.files || []
      selectedFile.value = file || null
      error.value = ''
      report.value = null
    }

    const clear = () => {
      selectedFile.value = null
      report.value = null
      error.value = ''
    }

    const analyze = async () => {
      if (!selectedFile.value) {
        return
      }

      const formData = new FormData()
      formData.append('file', selectedFile.value)

      isAnalyzing.value = true
      error.value = ''

      try {
        const response = await fetch(`${apiBaseUrl.value}/api/v1/mobile/analyze`, {
          method: 'POST',
          body: formData,
        })

        if (!response.ok) {
          const body = await response.text()
          throw new Error(body || `Analysis failed with ${response.status}`)
        }

        const payload = await response.json()
        report.value = {
          ...payload.report,
          risk_score: payload.risk_score ?? 0,
        }
      } catch (err) {
        error.value = err?.message || 'Failed to analyze APK'
      } finally {
        isAnalyzing.value = false
      }
    }

    const severityClass = (severity) => {
      switch (severity) {
        case 'Critical':
          return 'bg-rose-500/15 text-rose-300 border border-rose-500/20'
        case 'High':
          return 'bg-orange-500/15 text-orange-300 border border-orange-500/20'
        case 'Medium':
          return 'bg-yellow-500/15 text-yellow-200 border border-yellow-500/20'
        case 'Low':
          return 'bg-blue-500/15 text-blue-200 border border-blue-500/20'
        default:
          return 'bg-gray-700 text-gray-200 border border-gray-600'
      }
    }

    return {
      apiBaseUrl,
      clear,
      analyze,
      error,
      isAnalyzing,
      onSelectFile,
      report,
      severityClass,
      selectedFileName,
    }
  },
}
</script>
