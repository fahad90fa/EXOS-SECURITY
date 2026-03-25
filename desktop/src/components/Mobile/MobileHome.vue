<template>
  <section class="p-6 h-full overflow-auto">
    <div class="max-w-6xl mx-auto space-y-6">
      <header class="space-y-2">
        <p class="text-xs uppercase tracking-[0.3em] text-cyan-400">MobileGuard</p>
        <h2 class="text-3xl font-bold text-white">Mobile Testing</h2>
        <p class="text-gray-400">Static APK triage, permission review, and runtime test orchestration in one place.</p>
      </header>

      <div class="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <article v-for="card in cards" :key="card.title" class="bg-gray-800 border border-gray-700 rounded-xl p-5">
          <p class="text-sm text-gray-400">{{ card.label }}</p>
          <h3 class="mt-2 text-lg font-semibold text-white">{{ card.title }}</h3>
          <p class="mt-2 text-sm text-gray-300">{{ card.body }}</p>
        </article>
      </div>

      <ApkUpload />

      <div class="grid gap-4 lg:grid-cols-2">
        <section class="bg-gray-800 border border-gray-700 rounded-xl p-5">
          <h3 class="text-lg font-semibold text-white mb-3">What’s included</h3>
          <ul class="space-y-2 text-sm text-gray-300">
            <li>APK upload and archive inspection</li>
            <li>Manifest and permissions audit</li>
            <li>Resource URL and secret extraction</li>
            <li>Signature scheme checks and risk scoring</li>
          </ul>
        </section>
        <section class="bg-gray-800 border border-gray-700 rounded-xl p-5">
          <h3 class="text-lg font-semibold text-white mb-3">CLI support</h3>
          <code class="block rounded-lg bg-gray-900 px-4 py-3 text-cyan-300 text-sm overflow-x-auto">
nexus mobile analyze app.apk
nexus mobile report app.apk
          </code>
        </section>
      </div>
    </div>
  </section>
</template>

<script>
import ApkUpload from './ApkUpload.vue'

export default {
  name: 'MobileHome',
  components: {
    ApkUpload,
  },
  setup() {
    const cards = [
      { label: 'Static', title: 'APK Parsing', body: 'Inspect archive contents, recover resources, and locate embedded endpoints.' },
      { label: 'Security', title: 'Manifest Review', body: 'Flag cleartext traffic, debuggable builds, and risky exported components.' },
      { label: 'Secrets', title: 'String Mining', body: 'Extract URLs, API paths, and secret-like patterns from bundled text.' },
      { label: 'Integrity', title: 'Signing Checks', body: 'Track signature scheme presence and surface signing gaps.' }
    ]

    return { cards }
  }
}
</script>
