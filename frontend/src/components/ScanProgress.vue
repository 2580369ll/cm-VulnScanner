<template>
  <div class="scan-progress">
    <el-progress
      :percentage="percentage"
      :status="status"
      :stroke-width="16"
    />
    <p style="margin-top:8px;color:#666;font-size:13px;">
      已扫描 {{ scanned }} / {{ total }} 个端点
      <span v-if="vulns > 0" style="color:#e94560;">| 发现 {{ vulns }} 个漏洞</span>
    </p>
  </div>
</template>

<script setup>
import { computed } from 'vue'

const props = defineProps({
  scanned: { type: Number, default: 0 },
  total: { type: Number, default: 0 },
  vulns: { type: Number, default: 0 },
  isDone: { type: Boolean, default: false },
  isError: { type: Boolean, default: false },
})

const percentage = computed(() => {
  if (props.total === 0) return 0
  return Math.min(Math.round((props.scanned / props.total) * 100), 100)
})

const status = computed(() => {
  if (props.isError) return 'exception'
  if (props.isDone) return 'success'
  return ''
})
</script>
