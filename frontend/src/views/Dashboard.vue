<template>
  <div class="dashboard">
    <h2 style="margin-bottom:20px;">📊 仪表盘</h2>

    <!-- 统计卡片 -->
    <el-row :gutter="20" style="margin-bottom:20px;">
      <el-col :span="6">
        <el-card shadow="hover" class="stat-card">
          <div class="stat-icon" style="background:#e3f2fd;">📋</div>
          <div class="stat-info">
            <h3>{{ stats.total_tasks || 0 }}</h3>
            <p>总扫描任务</p>
          </div>
        </el-card>
      </el-col>
      <el-col :span="6">
        <el-card shadow="hover" class="stat-card">
          <div class="stat-icon" style="background:#fff3e0;">✅</div>
          <div class="stat-info">
            <h3>{{ stats.completed_tasks || 0 }}</h3>
            <p>已完成任务</p>
          </div>
        </el-card>
      </el-col>
      <el-col :span="6">
        <el-card shadow="hover" class="stat-card">
          <div class="stat-icon" style="background:#fce4ec;">🐛</div>
          <div class="stat-info">
            <h3 style="color:#e94560;">{{ stats.total_vulns || 0 }}</h3>
            <p>发现漏洞总数</p>
          </div>
        </el-card>
      </el-col>
      <el-col :span="6">
        <el-card shadow="hover" class="stat-card">
          <div class="stat-icon" style="background:#e8f5e9;">⚡</div>
          <div class="stat-info">
            <h3>{{ vulnRate }}%</h3>
            <p>漏洞检出率</p>
          </div>
        </el-card>
      </el-col>
    </el-row>

    <!-- 图表行 -->
    <el-row :gutter="20" style="margin-bottom:20px;">
      <el-col :span="12">
        <el-card>
          <template #header><strong>漏洞类型分布</strong></template>
          <div ref="typeChartRef" style="height:300px;"></div>
        </el-card>
      </el-col>
      <el-col :span="12">
        <el-card>
          <template #header><strong>最近任务</strong></template>
          <el-table :data="recentTasks" style="width:100%;" v-loading="loading">
            <el-table-column prop="target_url" label="目标" show-overflow-tooltip />
            <el-table-column prop="status" label="状态" width="100">
              <template #default="{ row }">
                <el-tag :type="statusType(row.status)">{{ row.status }}</el-tag>
              </template>
            </el-table-column>
            <el-table-column prop="total_vulns" label="漏洞数" width="80" />
            <el-table-column label="操作" width="100">
              <template #default="{ row }">
                <el-button size="small" @click="$router.push(`/tasks/${row.id}`)">详情</el-button>
              </template>
            </el-table-column>
          </el-table>
        </el-card>
      </el-col>
    </el-row>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { taskApi } from '../api/tasks'
import * as echarts from 'echarts'

const stats = ref({})
const recentTasks = ref([])
const loading = ref(false)
const typeChartRef = ref(null)

const vulnRate = computed(() => {
  if (!stats.value.completed_tasks || stats.value.completed_tasks === 0) return 0
  return Math.round((stats.value.total_vulns || 0) / stats.value.completed_tasks * 100)
})

function statusType(status) {
  const map = { pending: 'info', running: 'warning', completed: 'success', failed: 'danger' }
  return map[status] || 'info'
}

async function loadData() {
  loading.value = true
  try {
    const [statsRes, tasksRes] = await Promise.all([
      taskApi.stats(),
      taskApi.list(1, 10),
    ])
    stats.value = statsRes.data
    recentTasks.value = tasksRes.data.tasks || []
  } catch (e) {
    console.error('加载数据失败:', e)
  }
  loading.value = false
}

function renderChart() {
  if (!typeChartRef.value) return
  const chart = echarts.init(typeChartRef.value)

  const data = stats.value.vuln_by_type || {}
  chart.setOption({
    tooltip: { trigger: 'item' },
    legend: { bottom: '0%' },
    series: [{
      type: 'pie',
      radius: ['45%', '75%'],
      avoidLabelOverlap: false,
      itemStyle: { borderRadius: 6, borderColor: '#fff', borderWidth: 2 },
      label: { show: true, formatter: '{b}\n{d}%' },
      data: Object.entries(data).map(([name, value]) => ({
        name: name === 'sqli' ? 'SQL注入' : name === 'xss' ? 'XSS' : name === 'file_upload' ? '文件上传' : name,
        value,
      })),
    }],
  })

  window.addEventListener('resize', () => chart.resize())
}

onMounted(async () => {
  await loadData()
  setTimeout(renderChart, 200)
})
</script>

<style scoped>
.dashboard h2 { color: #1a1a2e; }
.stat-card { display: flex; align-items: center; padding: 10px; }
.stat-card :deep(.el-card__body) { display: flex; align-items: center; width: 100%; padding: 15px; }
.stat-icon { width: 52px; height: 52px; border-radius: 12px; display: flex; align-items: center; justify-content: center; font-size: 24px; margin-right: 15px; flex-shrink: 0; }
.stat-info h3 { margin: 0; font-size: 28px; color: #1a1a2e; }
.stat-info p { margin: 4px 0 0; color: #999; font-size: 13px; }
</style>
