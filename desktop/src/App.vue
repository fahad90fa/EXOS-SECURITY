<template>
  <div class="h-screen flex flex-col bg-gray-900 text-white">
    <!-- Header -->
    <header class="bg-gray-800 border-b border-gray-700 px-4 py-3">
      <div class="flex items-center justify-between">
        <h1 class="text-xl font-bold text-blue-400">🔍 Nexus Sentinel</h1>
        <div class="flex items-center space-x-4">
          <span class="text-sm text-gray-400">Advanced Web Security Scanner</span>
          <div class="flex space-x-2">
            <button
              v-for="route in routes"
              :key="route.path"
              @click="$router.push(route.path)"
              :class="[
                'px-3 py-1 rounded text-sm transition-colors',
                $route.path === route.path
                  ? 'bg-blue-600 text-white'
                  : 'bg-gray-700 hover:bg-gray-600'
              ]"
            >
              {{ route.name }}
            </button>
          </div>
        </div>
      </div>
    </header>

    <!-- Main Content -->
    <main class="flex-1 overflow-hidden">
      <router-view />
    </main>

    <!-- Status Bar -->
    <footer class="bg-gray-800 border-t border-gray-700 px-4 py-2">
      <div class="flex items-center justify-between text-sm text-gray-400">
        <div class="flex items-center space-x-4">
          <span>Status: {{ connectionStatus }}</span>
          <span>Version: 0.1.0</span>
        </div>
        <div class="flex items-center space-x-4">
          <span>Active Scans: {{ activeScans }}</span>
          <span>Proxy: {{ proxyStatus }}</span>
        </div>
      </div>
    </footer>
  </div>
</template>

<script>
import { ref, onMounted } from 'vue'

export default {
  name: 'App',
  setup() {
    const connectionStatus = ref('Connected')
    const activeScans = ref(0)
    const proxyStatus = ref('Stopped')

    const routes = [
      { path: '/', name: 'Dashboard' },
      { path: '/proxy', name: 'Proxy' },
      { path: '/scanner', name: 'Scanner' },
      { path: '/crawler', name: 'Crawler' },
      { path: '/mobile', name: 'Mobile' },
      { path: '/reports', name: 'Reports' },
      { path: '/settings', name: 'Settings' }
    ]

    onMounted(() => {
      // Check connection status periodically
      setInterval(() => {
        // In real implementation, check API connectivity
        connectionStatus.value = 'Connected'
      }, 5000)
    })

    return {
      connectionStatus,
      activeScans,
      proxyStatus,
      routes
    }
  }
}
</script>

<style>
/* Global styles */
* {
  margin: 0;
  padding: 0;
  box-sizing: border-box;
}

html, body {
  height: 100%;
  font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
}

/* Scrollbar styling */
::-webkit-scrollbar {
  width: 8px;
}

::-webkit-scrollbar-track {
  background: #374151;
}

::-webkit-scrollbar-thumb {
  background: #6b7280;
  border-radius: 4px;
}

::-webkit-scrollbar-thumb:hover {
  background: #9ca3af;
}
</style>
