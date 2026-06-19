<template>
  <div class="task-detail">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:20px;">
      <h2>🔍 任务详情</h2>
      <el-button @click="$router.push('/tasks')">← 返回列表</el-button>
    </div>

    <!-- 基本信息 -->
    <el-card style="margin-bottom:20px;" v-loading="loading">
      <template #header><strong>基本信息</strong></template>
      <el-descriptions :column="2" border>
        <el-descriptions-item label="目标 URL">{{ task.target_url }}</el-descriptions-item>
        <el-descriptions-item label="状态">
          <el-tag :type="statusType(task.status)">{{ statusLabel(task.status) }}</el-tag>
        </el-descriptions-item>
        <el-descriptions-item label="扫描深度">{{ task.scan_depth }} 层</el-descriptions-item>
        <el-descriptions-item label="漏洞类型">
          <el-tag v-for="t in (task.vuln_types || [])" :key="t" size="small" style="margin:0 3px;">{{ t }}</el-tag>
        </el-descriptions-item>
        <el-descriptions-item label="扫描端点">{{ task.scanned_endpoints || 0 }} / {{ task.total_endpoints || 0 }}</el-descriptions-item>
        <el-descriptions-item label="发现漏洞">
          <span :style="{color:'#e94560',fontWeight:'bold',fontSize:'18px'}">{{ task.total_vulns || 0 }}</span>
        </el-descriptions-item>
        <el-descriptions-item label="WAF 检测" :span="2">
          <span v-if="task.waf_detected">🛡️ {{ task.waf_detected }}</span>
          <span v-else style="color:#999;">未检测到 WAF</span>
        </el-descriptions-item>
        <el-descriptions-item label="创建时间">{{ formatTime(task.created_at) }}</el-descriptions-item>
        <el-descriptions-item label="完成时间">{{ formatTime(task.completed_at) }}</el-descriptions-item>
      </el-descriptions>
    </el-card>

    <!-- 实时进度 (扫描中时显示) -->
    <el-card v-if="task.status === 'running'" style="margin-bottom:20px;">
      <template #header><strong>⚡ 实时扫描进度</strong></template>
      <ScanProgress
        :scanned="task.scanned_endpoints || 0"
        :total="task.total_endpoints || 0"
        :vulns="task.total_vulns || 0"
        :is-done="task.status === 'completed'"
        :is-error="task.status === 'failed'"
      />

      <!-- 实时日志 -->
      <div v-if="wsMessages.length > 0" class="live-log">
        <h4>实时日志</h4>
        <div v-for="(msg, i) in wsMessages.slice(-20)" :key="i" class="log-entry">
          <span class="log-time">{{ new Date().toLocaleTimeString() }}</span>
          <span v-if="msg.type === 'vulnerability_found'" style="color:#e94560;">
            🐛 发现漏洞: {{ msg.vuln_type }} ({{ msg.severity }}) — {{ msg.endpoint }}
          </span>
          <span v-else-if="msg.type === 'endpoint_scanned'" style="color:#67c23a;">
            ✅ 端点扫描完成 ({{ msg.current }}/{{ msg.total }})
          </span>
          <span v-else-if="msg.type === 'scan_complete'" style="color:#409eff;">
            🎉 扫描完成！共发现 {{ msg.total_vulns }} 个漏洞
          </span>
          <span v-else>{{ msg.type }}</span>
        </div>
      </div>
    </el-card>

    <!-- 扫描完成时自动加载结果 -->
    <el-card v-if="task.status === 'completed'">
      <template #header>
        <strong>🐛 漏洞结果 ({{ vulnerabilities.length }})</strong>
      </template>
      <div v-if="vulnerabilities.length === 0" style="text-align:center;padding:40px;color:#999;">
        <p style="font-size:48px;">🎉</p>
        <p>未发现漏洞</p>
      </div>
      <VulnCard v-for="vuln in vulnerabilities" :key="vuln.id" :vuln="vuln" />
    </el-card>
  </div>
</template>

<script setup>
import { ref, watch, onMounted } from 'vue'
import { useRoute } from 'vue-router'
import { taskApi, resultApi } from '../api/tasks'
import { useWebSocket } from '../api/results'
import { ElMessage } from 'element-plus'
import ScanProgress from '../components/ScanProgress.vue'
import VulnCard from '../components/VulnCard.vue'

const route = useRoute()
const taskId = route.params.id

const task = ref({})
const vulnerabilities = ref([])
const loading = ref(false)

// WebSocket 实时连接 — 用 latestMessage 替代 deep watch
const { connected, messages: wsMessages, latestMessage } = useWebSocket(taskId)

function statusType(s) {
  const m = { pending: 'info', running: 'warning', completed: 'success', failed: 'danger' }
  return m[s] || 'info'
}
function statusLabel(s) {
  const m = { pending: '等待中', running: '扫描中', completed: '已完成', failed: '失败' }
  return m[s] || s
}
function formatTime(ts) {
  if (!ts) return '-'
  return new Date(ts).toLocaleString('zh-CN')
}

async function loadTask() {
  loading.value = true
  try {
    const res = await taskApi.get(taskId)
    task.value = res.data.task
  } catch (e) {
    ElMessage.error('加载任务失败')
  }
  loading.value = false
}

async function loadResults() {
  try {
    const res = await resultApi.listByTask(taskId)
    vulnerabilities.value = res.data.vulnerabilities || []
  } catch (e) {
    // 静默失败
  }
}

// 监听最新 WebSocket 消息 (latestMessage 是单个 ref，watch 直接生效)
watch(latestMessage, (msg) => {
  if (!msg) return

  switch (msg.type) {
    case 'scan_complete':
    case 'scan_error':
      loadTask()
      loadResults()
      break
    case 'crawl_complete':
      task.value.total_endpoints = msg.total_endpoints
      break
    case 'endpoint_scanned':
      task.value.scanned_endpoints = msg.current
      task.value.total_endpoints = msg.total
      break
    case 'waf_detected':
      task.value.waf_detected = msg.waf
      break
    case 'vulnerability_found':
      task.value.total_vulns = (task.value.total_vulns || 0) + 1
      break
  }
})

onMounted(() => {
  loadTask()
  loadResults()
})
</script>

<style scoped>
.live-log { background: #1a1a2e; border-radius: 8px; padding: 15px; margin-top: 15px; max-height: 350px; overflow-y: auto; }
.live-log h4 { color: #53a8b6; margin-bottom: 10px; }
.log-entry { padding: 5px 0; font-family: monospace; font-size: 13px; color: #ccc; border-bottom: 1px solid #0f3460; }
.log-time { color: #888; margin-right: 10px; }
</style>
