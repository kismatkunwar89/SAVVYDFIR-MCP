<template>
  <div class="mcp-dashboard">
    <header class="dfir-header">
      <div class="brand">SAVVYDFIR-MCP</div>
      <div class="status-pill running">
        <span class="blink">▶</span> Listening for Agent Pipeline (Bridge port 8000)...
      </div>
    </header>

    <div class="dashboard-content">
      <div class="graph-wrapper">
        <GraphPanel
          :graphData="graphData"
          :loading="loading"
          @refresh="fetchGraph"
        />
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted, onUnmounted } from 'vue'
import GraphPanel from './components/GraphPanel.vue'

const graphData = ref(null)
const loading = ref(false)
let pollTimer = null

async function fetchGraph() {
  try {
    const res = await fetch('http://localhost:8000/api/graph')
    if (res.ok) {
        const data = await res.json()
        graphData.value = data
    }
  } catch (err) {
    console.debug("Backend graph API offline or unreachable.")
  }
}

onMounted(() => {
  // Initial fetch
  fetchGraph()
  // Atomic live polling (2x a second for fast visual responsiveness)
  pollTimer = setInterval(fetchGraph, 1000)
})

onUnmounted(() => {
  if (pollTimer) clearInterval(pollTimer)
})
</script>

<style>
/* Global Resets */
body {
  margin: 0;
  padding: 0;
  background: #0d0d0f;
  color: #e0e0e0;
  font-family: 'JetBrains Mono', 'Fira Code', monospace;
}

.mcp-dashboard {
  display: flex;
  flex-direction: column;
  height: 100vh;
  width: 100vw;
  overflow: hidden;
}

.dfir-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 16px 32px;
  background: #111114;
  border-bottom: 1px solid #222;
  flex-shrink: 0;
  box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.5);
  z-index: 10;
}

.brand {
  font-size: 20px;
  font-weight: 700;
  color: #00ff88;
  letter-spacing: 3px;
}

.status-pill.running {
  background: #1a2a1a;
  color: #00ff88;
  padding: 8px 18px;
  border-radius: 20px;
  font-size: 13px;
  font-weight: 600;
  border: 1px solid #1e3a1e;
}

@keyframes blink {
  0% { opacity: 1; }
  50% { opacity: 0; }
  100% { opacity: 1; }
}
.blink {
  animation: blink 1.5s infinite;
  display: inline-block;
  margin-right: 6px;
}

.dashboard-content {
  flex: 1;
  display: flex;
  padding: 24px;
}

.graph-wrapper {
  flex: 1;
  background: #111114;
  border: 1px solid #222;
  border-radius: 8px;
  display: flex;
  flex-direction: column;
  overflow: hidden;
  box-shadow: 0 0 20px rgba(0,0,0,0.5);
}

/* Make GraphPanel fill the whole box perfectly */
.graph-panel {
  display: flex;
  flex-direction: column;
  width: 100%;
  height: 100%;
}
.graph-container {
  flex: 1;
  position: relative;
  overflow: hidden;
}
.graph-view, .graph-svg {
  width: 100%;
  height: 100%;
  min-height: 500px;
}
</style>
