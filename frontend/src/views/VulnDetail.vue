<template>
  <div class="vuln-detail" v-loading="loading">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:20px;">
      <h2>🐛 漏洞详情</h2>
      <el-button @click="$router.back()">← 返回</el-button>
    </div>

    <el-card v-if="vuln">
      <!-- 漏洞概要 -->
      <div class="vuln-header" :style="{ borderLeftColor: severityColor }">
        <div>
          <SeverityTag :severity="vuln.severity" size="large" />
          <span class="vuln-type">{{ typeLabel(vuln.vuln_type) }}</span>
        </div>
        <div class="vuln-meta">
          <p><strong>端点:</strong> <code>{{ vuln.endpoint }}</code></p>
          <p><strong>参数:</strong> {{ vuln.parameter }} ({{ vuln.method }})</p>
          <p><strong>发现时间:</strong> {{ formatTime(vuln.created_at) }}</p>
          <p v-if="vuln.payload_variant">
            <strong>绕过变体:</strong>
            <el-tag size="small">{{ vuln.payload_variant }}</el-tag>
          </p>
        </div>
      </div>

      <el-divider />

      <!-- Payload 信息 -->
      <h3>💉 Payload</h3>
      <el-input
        :model-value="vuln.payload"
        type="textarea"
        :rows="2"
        readonly
        style="font-family:monospace;"
      />

      <!-- 漏洞描述 -->
      <h3 style="margin-top:20px;">📝 漏洞描述</h3>
      <el-alert
        :title="vuln.description || '无描述'"
        type="warning"
        :closable="false"
        show-icon
      />

      <!-- HTTP 请求与响应详情 -->
      <h3 style="margin-top:20px;">📡 HTTP 请求与响应</h3>
      <HttpRequest
        :request-text="vuln.request_raw"
        :response-text="vuln.response_raw"
      />

      <!-- 响应证据 -->
      <div v-if="vuln.response_evidence" style="margin-top:15px;">
        <h3>🔬 漏洞证据</h3>
        <el-alert
          :title="vuln.response_evidence"
          type="error"
          :closable="false"
          show-icon
        />
      </div>

      <el-divider />

      <!-- PoC -->
      <h3>🧪 PoC (概念验证)</h3>
      <div class="poc-section">
        <pre><code>{{ vuln.poc || '无 PoC' }}</code></pre>
        <el-button type="primary" size="small" @click="copyPoc">
          📋 复制 PoC
        </el-button>
      </div>

      <!-- 修复建议 -->
      <h3 style="margin-top:20px;">🛡️ 修复建议</h3>
      <el-alert
        :title="vuln.remediation || '无修复建议'"
        type="success"
        :closable="false"
        show-icon
      />
    </el-card>

    <!-- 加载失败 -->
    <el-empty v-else description="漏洞不存在或已删除" />
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { useRoute } from 'vue-router'
import { resultApi } from '../api/tasks'
import { ElMessage } from 'element-plus'
import SeverityTag from '../components/SeverityTag.vue'
import HttpRequest from '../components/HttpRequest.vue'

const route = useRoute()
const vulnId = route.params.id

const vuln = ref(null)
const loading = ref(false)

const severityColors = {
  critical: '#dc3545',
  high: '#fd7e14',
  medium: '#ffc107',
  low: '#28a745',
  info: '#17a2b8',
}

const severityColor = computed(() => severityColors[vuln.value?.severity] || '#6c757d')

function typeLabel(type) {
  const m = {
    sqli: 'SQL 注入',
    xss: '跨站脚本 (XSS)',
    file_upload: '文件上传漏洞',
  }
  return m[type] || type
}

function formatTime(ts) {
  if (!ts) return '-'
  return new Date(ts).toLocaleString('zh-CN')
}

async function copyPoc() {
  try {
    await navigator.clipboard.writeText(vuln.value?.poc || '')
    ElMessage.success('PoC 已复制到剪贴板')
  } catch {
    ElMessage.error('复制失败')
  }
}

onMounted(async () => {
  loading.value = true
  try {
    const res = await resultApi.get(vulnId)
    vuln.value = res.data.vulnerability
  } catch (e) {
    ElMessage.error('加载漏洞详情失败')
  }
  loading.value = false
})
</script>

<style scoped>
.vuln-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  padding: 15px;
  background: #f8f9fa;
  border-radius: 8px;
  border-left: 5px solid #ccc;
}
.vuln-type {
  font-size: 20px;
  font-weight: bold;
  margin-left: 10px;
  color: #1a1a2e;
}
.vuln-meta p { margin: 5px 0; }
code { background: #f0f0f0; padding: 2px 6px; border-radius: 3px; word-break: break-all; }
.poc-section { background: #f8f9fa; padding: 15px; border-radius: 8px; }
.poc-section pre { background: #282c34; color: #abb2bf; padding: 15px; border-radius: 6px; overflow-x: auto; font-size: 14px; }
.poc-section pre code { background: none; padding: 0; color: inherit; }
h3 { color: #1a1a2e; margin: 15px 0 10px; }
</style>
