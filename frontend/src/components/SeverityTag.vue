<template>
  <div class="severity-tag">
    <el-tag
      :type="tagType"
      :effect="effect"
      :size="size"
      disable-transitions
    >
      {{ label }}
    </el-tag>
  </div>
</template>

<script setup>
import { computed } from 'vue'

const props = defineProps({
  severity: { type: String, default: 'info' },
  effect: { type: String, default: 'dark' },
  size: { type: String, default: 'default' },
})

const severityMap = {
  critical: { type: '', label: '严重', color: '#dc3545' },
  high: { type: 'danger', label: '高危' },
  medium: { type: 'warning', label: '中危' },
  low: { type: 'success', label: '低危' },
  info: { type: 'info', label: '信息' },
}

const tagType = computed(() => severityMap[props.severity]?.type || 'info')
const label = computed(() => severityMap[props.severity]?.label || props.severity)
</script>
