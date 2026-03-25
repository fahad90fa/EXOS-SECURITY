import { createApp } from 'vue'
import { createPinia } from 'pinia'
import { createRouter, createWebHistory } from 'vue-router'
import App from './App.vue'
import './style.css'

// Import components
import Dashboard from './components/Dashboard.vue'
import Proxy from './components/Proxy.vue'
import Scanner from './components/Scanner.vue'
import Crawler from './components/Crawler.vue'
import Reports from './components/Reports.vue'
import Settings from './components/Settings.vue'

const routes = [
  { path: '/', component: Dashboard },
  { path: '/proxy', component: Proxy },
  { path: '/scanner', component: Scanner },
  { path: '/crawler', component: Crawler },
  { path: '/reports', component: Reports },
  { path: '/settings', component: Settings }
]

const router = createRouter({
  history: createWebHistory(),
  routes
})

const app = createApp(App)
app.use(createPinia())
app.use(router)

app.mount('#app')
