<template>
  <div class="p-6 h-full overflow-auto">
    <div class="max-w-7xl mx-auto">
      <!-- Welcome Section -->
      <div class="mb-8">
        <h2 class="text-3xl font-bold text-white mb-2">Dashboard</h2>
        <p class="text-gray-400">Welcome to Nexus Sentinel - Advanced Web Application Security Scanner</p>
      </div>

      <!-- Stats Cards -->
      <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
        <div class="bg-gray-800 rounded-lg p-6 border border-gray-700">
          <div class="flex items-center">
            <div class="p-2 bg-green-600 rounded-lg">
              <svg class="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path>
              </svg>
            </div>
            <div class="ml-4">
              <p class="text-sm text-gray-400">Total Scans</p>
              <p class="text-2xl font-bold text-white">{{ stats.totalScans }}</p>
            </div>
          </div>
        </div>

        <div class="bg-gray-800 rounded-lg p-6 border border-gray-700">
          <div class="flex items-center">
            <div class="p-2 bg-red-600 rounded-lg">
              <svg class="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16.5c-.77.833.192 2.5 1.732 2.5z"></path>
              </svg>
            </div>
            <div class="ml-4">
              <p class="text-sm text-gray-400">Vulnerabilities</p>
              <p class="text-2xl font-bold text-white">{{ stats.totalVulns }}</p>
            </div>
          </div>
        </div>

        <div class="bg-gray-800 rounded-lg p-6 border border-gray-700">
          <div class="flex items-center">
            <div class="p-2 bg-blue-600 rounded-lg">
              <svg class="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"></path>
              </svg>
            </div>
            <div class="ml-4">
              <p class="text-sm text-gray-400">Active Scans</p>
              <p class="text-2xl font-bold text-white">{{ stats.activeScans }}</p>
            </div>
          </div>
        </div>

        <div class="bg-gray-800 rounded-lg p-6 border border-gray-700">
          <div class="flex items-center">
            <div class="p-2 bg-purple-600 rounded-lg">
              <svg class="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z"></path>
              </svg>
            </div>
            <div class="ml-4">
              <p class="text-sm text-gray-400">Coverage Score</p>
              <p class="text-2xl font-bold text-white">{{ stats.coverage }}%</p>
            </div>
          </div>
        </div>
      </div>

      <!-- Quick Actions -->
      <div class="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
        <div class="bg-gray-800 rounded-lg p-6 border border-gray-700">
          <h3 class="text-lg font-semibold text-white mb-4">Quick Actions</h3>
          <div class="space-y-3">
            <button
              @click="$router.push('/scanner')"
              class="w-full bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded transition-colors"
            >
              🚀 Start New Scan
            </button>
            <button
              @click="$router.push('/proxy')"
              class="w-full bg-green-600 hover:bg-green-700 text-white px-4 py-2 rounded transition-colors"
            >
              🔍 Start Proxy Server
            </button>
            <button
              @click="$router.push('/crawler')"
              class="w-full bg-purple-600 hover:bg-purple-700 text-white px-4 py-2 rounded transition-colors"
            >
              🕷️ Start Web Crawler
            </button>
          </div>
        </div>

        <div class="bg-gray-800 rounded-lg p-6 border border-gray-700">
          <h3 class="text-lg font-semibold text-white mb-4">Recent Activity</h3>
          <div class="space-y-2">
            <div v-for="activity in recentActivity" :key="activity.id" class="flex items-center justify-between py-2 border-b border-gray-700 last:border-b-0">
              <div>
                <p class="text-sm text-white">{{ activity.action }}</p>
                <p class="text-xs text-gray-400">{{ activity.target }}</p>
              </div>
              <span class="text-xs text-gray-500">{{ activity.time }}</span>
            </div>
          </div>
        </div>
      </div>

      <!-- System Status -->
      <div class="bg-gray-800 rounded-lg p-6 border border-gray-700">
        <h3 class="text-lg font-semibold text-white mb-4">System Status</h3>
        <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div class="flex items-center justify-between">
            <span class="text-gray-400">API Server</span>
            <span class="flex items-center">
              <div class="w-2 h-2 bg-green-500 rounded-full mr-2"></div>
              <span class="text-green-400">Running</span>
            </span>
          </div>
          <div class="flex items-center justify-between">
            <span class="text-gray-400">Database</span>
            <span class="flex items-center">
              <div class="w-2 h-2 bg-green-500 rounded-full mr-2"></div>
              <span class="text-green-400">Connected</span>
            </span>
          </div>
          <div class="flex items-center justify-between">
            <span class="text-gray-400">AI Service</span>
            <span class="flex items-center">
              <div class="w-2 h-2 bg-yellow-500 rounded-full mr-2"></div>
              <span class="text-yellow-400">Initializing</span>
            </span>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script>
import { ref, onMounted } from 'vue'

export default {
  name: 'Dashboard',
  setup() {
    const stats = ref({
      totalScans: 0,
      totalVulns: 0,
      activeScans: 0,
      coverage: 0
    })

    const recentActivity = ref([
      {
        id: 1,
        action: 'Scan completed',
        target: 'example.com',
        time: '2 minutes ago'
      },
      {
        id: 2,
        action: 'Vulnerability found',
        target: 'SQL Injection in login.php',
        time: '5 minutes ago'
      },
      {
        id: 3,
        action: 'Proxy started',
        target: '127.0.0.1:8080',
        time: '10 minutes ago'
      }
    ])

    onMounted(() => {
      // Load dashboard stats
      loadStats()
    })

    const loadStats = async () => {
      try {
        // In real implementation, fetch from API
        stats.value = {
          totalScans: 15,
          totalVulns: 23,
          activeScans: 1,
          coverage: 95
        }
      } catch (error) {
        console.error('Failed to load stats:', error)
      }
    }

    return {
      stats,
      recentActivity,
      loadStats
    }
  }
}
</script>
