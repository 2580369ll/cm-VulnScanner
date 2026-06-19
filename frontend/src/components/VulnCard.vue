<template>
  <el-card class="vuln-card" :style="{ borderLeft: `4px solid ${color}` }" shadow="hover">
    <template #header>
      <div class="card-header">
        <severity-tag :severity="vuln.severity" />
        <strong style="margin-left:10px;text-transform:uppercase;">{{ vuln.vuln_type }}</strong>
        <el-button
          type="primary"
          size="small"
          style="margin-left:auto;"
          @click="$router.push(`/results/${vuln.id}`)"
        >
          查看详情
        </el-button>
      </div>
    </template>

    <div class="card-body">
      <p><strong>端点:</strong> <code>{{ vuln.endpoint }}</code></p>
      <p><strong>参数:</strong> {{ vuln.parameter }} ({{ vuln.method }})</p>
      <p v-if="vuln.payload">
        <strong>Payload:</strong>
        <el-tag size="small" style="font-family:monospace;">{{ truncate(vuln.payload, 120) }}</el-tag>
      </p>
      <p v-if="vuln.description" style="color:#666;margin-top:10px;">{{ vuln.description }}</p>
    </div>
  </el-card>
</template>

<script setup>
import SeverityTag from './SeverityTag.vue'

const props = defineProps({
  vuln: { type: Object, required: true },
})

const severityColors = {
  critical: '#dc3545',
  high: '#fd7e14',
  medium: '#ffc107',
  low: '#28a745',
  info: '#17a2b8',
}

const color = severityColors[props.vuln.severity] || '#6c757d'

function truncate(text, max) {
  if (!text) return ''
  return text.length > max ? text.slice(0, max) + '...' : text
}
</script>

<style scoped>
.vuln-card { margin-bottom: 15px; }
.card-header { display: flex; align-items: center; }
code { background: #f0f0f0; padding: 2px 6px; border-radius: 3px; word-break: break-all; }
</style>
