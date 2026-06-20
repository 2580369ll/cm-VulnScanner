<template>
  <div class="task-list">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:20px;">
      <h2>📋 任务列表</h2>
      <el-button type="danger" size="large" @click="$router.push('/tasks/create')">
        ➕ 创建任务
      </el-button>
    </div>

    <el-card>
      <el-table :data="tasks" v-loading="loading" stripe>
        <el-table-column prop="target_url" label="扫描目标" show-overflow-tooltip min-width="200" />
        <el-table-column prop="status" label="状态" width="100">
          <template #default="{ row }">
            <el-tag :type="statusType(row.status)" size="small">{{ statusLabel(row.status) }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="scan_depth" label="深度" width="70" />
        <el-table-column label="漏洞类型" width="180">
          <template #default="{ row }">
            <el-tag
              v-for="t in (row.vuln_types || [])"
              :key="t"
              size="small"
              style="margin:0 2px;"
            >
              {{ vulnLabel(t) }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="total_endpoints" label="端点" width="70" />
        <el-table-column label="漏洞" width="80">
          <template #default="{ row }">
            <span :style="{ color: row.total_vulns > 0 ? '#e94560' : '#999', fontWeight: row.total_vulns > 0 ? 'bold' : 'normal' }">
              {{ row.total_vulns || 0 }}
            </span>
          </template>
        </el-table-column>
        <el-table-column label="WAF" width="120" show-overflow-tooltip>
          <template #default="{ row }">
            <span v-if="row.waf_detected" style="color:#e6a23c;">🛡️ {{ row.waf_detected }}</span>
            <span v-else style="color:#999;">—</span>
          </template>
        </el-table-column>
        <el-table-column prop="created_at" label="创建时间" width="170">
          <template #default="{ row }">
            {{ formatTime(row.created_at) }}
          </template>
        </el-table-column>
        <el-table-column label="操作" width="150" fixed="right">
          <template #default="{ row }">
            <el-button size="small" @click="$router.push(`/tasks/${row.id}`)">详情</el-button>
            <el-button size="small" type="danger" @click="deleteTask(row)">删除</el-button>
          </template>
        </el-table-column>
      </el-table>

      <div style="margin-top:15px;text-align:right;">
        <el-pagination
          v-model:current-page="page"
          v-model:page-size="pageSize"
          :page-sizes="[10, 20, 50]"
          :total="total"
          layout="sizes, prev, pager, next, total"
          @current-change="loadTasks"
          @size-change="loadTasks"
        />
      </div>
    </el-card>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { taskApi } from '../api/tasks'
import { ElMessage, ElMessageBox } from 'element-plus'

const tasks = ref([])
const loading = ref(false)
const page = ref(1)
const pageSize = ref(20)
const total = ref(0)

function statusType(status) {
  const m = { pending: 'info', running: 'warning', completed: 'success', failed: 'danger' }
  return m[status] || 'info'
}

function statusLabel(status) {
  const m = { pending: '等待中', running: '扫描中', completed: '已完成', failed: '失败' }
  return m[status] || status
}

function vulnLabel(type) {
  const m = { sqli: 'SQLi', xss: 'XSS', file_upload: 'Upload', command_injection: 'CMDi', path_traversal: 'LFI', ssrf: 'SSRF', info_disclosure: 'InfoLeak', ssti: 'SSTI', idor: 'IDOR', open_redirect: 'Redirect', csrf: 'CSRF', nuclei: 'Nuclei' }
  return m[type] || type
}
function formatTime(ts) {
  if (!ts) return '-'
  return new Date(ts).toLocaleString('zh-CN')
}

async function loadTasks() {
  loading.value = true
  try {
    const res = await taskApi.list(page.value, pageSize.value)
    tasks.value = res.data.tasks || []
    total.value = res.data.total || 0
  } catch (e) {
    ElMessage.error('加载任务列表失败')
  }
  loading.value = false
}

async function deleteTask(row) {
  try {
    await ElMessageBox.confirm(`确定删除对 ${row.target_url} 的扫描结果？`, '确认删除', {
      type: 'warning',
    })
    await taskApi.delete(row.id)
    ElMessage.success('任务已删除')
    loadTasks()
  } catch (e) {
    // 取消删除
  }
}

onMounted(loadTasks)
</script>
