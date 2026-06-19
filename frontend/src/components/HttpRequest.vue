<template>
  <div class="http-request">
    <div v-if="requestText" class="section">
      <h4>📤 HTTP 请求</h4>
      <pre><code>{{ requestText }}</code></pre>
    </div>
    <div v-if="responseText" class="section">
      <h4>📥 HTTP 响应</h4>
      <pre><code>{{ responseText }}</code></pre>
    </div>
  </div>
</template>

<script setup>
defineProps({
  requestText: { type: String, default: '' },
  responseText: { type: String, default: '' },
})
</script>

<style scoped>
.section { margin: 15px 0; }
.section h4 { color: #1a1a2e; margin-bottom: 8px; }
pre {
  background: #282c34;
  color: #abb2bf;
  padding: 15px;
  border-radius: 6px;
  overflow-x: auto;
  font-size: 13px;
  line-height: 1.6;
  max-height: 400px;
  overflow-y: auto;
}
code { font-family: 'Fira Code', 'Consolas', monospace; }
</style>
