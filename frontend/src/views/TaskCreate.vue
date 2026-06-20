<template>
  <div class="task-create">
    <h2 style="margin-bottom:20px;">➕ 创建扫描任务</h2>

    <el-row :gutter="20">
      <!-- 左侧：目标配置 -->
      <el-col :span="12">
        <el-card shadow="hover" style="margin-bottom:20px;">
          <template #header><strong>🎯 扫描目标</strong></template>
          <el-form :model="form" :rules="rules" ref="formRef" label-position="top">
            <el-form-item label="目标 URL" prop="target_url">
              <el-input v-model="form.target_url" placeholder="https://example.com" size="large" />
            </el-form-item>

            <el-form-item label="快速填入靶场">
              <div class="target-chips">
                <el-tag v-for="t in targets" :key="t.url" type="info" class="target-chip"
                  @click="form.target_url = t.url" :effect="form.target_url === t.url ? 'dark' : 'plain'">
                  {{ t.label }}
                </el-tag>
              </div>
            </el-form-item>

            <el-form-item label="扫描深度">
              <el-radio-group v-model="form.scan_depth" size="small">
                <el-radio-button :value="1">浅层 (仅首页)</el-radio-button>
                <el-radio-button :value="2">中等 (2层链接)</el-radio-button>
                <el-radio-button :value="3">深层 (3层链接)</el-radio-button>
              </el-radio-group>
            </el-form-item>
          </el-form>
        </el-card>

        <!-- 高级选项 -->
        <el-card shadow="hover">
          <template #header>
            <strong>⚙️ 高级选项</strong>
            <span style="font-size:12px;color:#999;margin-left:8px;">选填</span>
          </template>
          <el-form label-position="top">
            <el-form-item label="Cookie (登录态)">
              <el-input v-model="form.custom_cookies" type="textarea" :rows="2"
                placeholder='{"sessionid": "abc123"}' />
            </el-form-item>
            <el-form-item label="自定义 Header">
              <el-input v-model="form.custom_headers" type="textarea" :rows="2"
                placeholder='{"Authorization": "Bearer token"}' />
            </el-form-item>
            <el-collapse>
              <el-collapse-item title="更多选项">
                <el-form-item label="自定义 Payload (JSON)">
                  <el-input v-model="form.custom_payloads" type="textarea" :rows="3"
                    placeholder='{"sqli": ["payload1"]}' />
                </el-form-item>
                <el-form-item label="HTTP 代理">
                  <el-input v-model="form.proxy" placeholder="http://127.0.0.1:8080" />
                </el-form-item>
              </el-collapse-item>
            </el-collapse>
          </el-form>
        </el-card>
      </el-col>

      <!-- 右侧：漏洞类型 -->
      <el-col :span="12">
        <el-card shadow="hover" style="margin-bottom:20px;">
          <template #header>
            <div style="display:flex;justify-content:space-between;align-items:center;">
              <strong>🐛 漏洞类型</strong>
              <div>
                <el-button size="small" @click="selectAll">全选</el-button>
                <el-button size="small" @click="deselectAll">清空</el-button>
                <el-dropdown @command="selectPreset" style="margin-left:4px;">
                  <el-button size="small">快捷预设 ▾</el-button>
                  <template #dropdown>
                    <el-dropdown-menu>
                      <el-dropdown-item command="top10">🔥 OWASP Top 10</el-dropdown-item>
                      <el-dropdown-item command="injection">💉 注入类</el-dropdown-item>
                      <el-dropdown-item command="access">🔑 访问控制类</el-dropdown-item>
                      <el-dropdown-item command="all">🧬 全部类型</el-dropdown-item>
                    </el-dropdown-menu>
                  </template>
                </el-dropdown>
              </div>
            </div>
          </template>

          <el-checkbox-group v-model="form.vuln_types">
            <!-- 注入类 -->
            <div class="vuln-group">
              <div class="vuln-group-title">💉 注入攻击</div>
              <el-checkbox label="sqli" border>🔍 SQL 注入</el-checkbox>
              <el-checkbox label="command_injection" border>💻 命令注入</el-checkbox>
              <el-checkbox label="ssti" border>🎨 模板注入 (SSTI)</el-checkbox>
              <el-checkbox label="xss" border>💉 跨站脚本 (XSS)</el-checkbox>
            </div>

            <!-- 访问控制 -->
            <div class="vuln-group">
              <div class="vuln-group-title">🔑 访问控制</div>
              <el-checkbox label="idor" border>🔑 越权访问 (IDOR)</el-checkbox>
              <el-checkbox label="csrf" border>🛡️ 跨站伪造 (CSRF)</el-checkbox>
              <el-checkbox label="open_redirect" border>↗️ URL 重定向</el-checkbox>
            </div>

            <!-- 服务端 -->
            <div class="vuln-group">
              <div class="vuln-group-title">🌐 服务端漏洞</div>
              <el-checkbox label="ssrf" border>🌐 SSRF</el-checkbox>
              <el-checkbox label="file_upload" border>📁 文件上传</el-checkbox>
              <el-checkbox label="path_traversal" border>📂 路径遍历</el-checkbox>
            </div>

            <!-- 信息类 -->
            <div class="vuln-group">
              <div class="vuln-group-title">🔓 信息与配置</div>
              <el-checkbox label="info_disclosure" border>🔓 信息泄露</el-checkbox>
              <el-checkbox label="nuclei" border>🧬 Nuclei 模板</el-checkbox>
            </div>
          </el-checkbox-group>

          <el-divider />

          <div style="text-align:right;">
            <span style="color:#999;margin-right:10px;">已选 {{ form.vuln_types.length }} / 12</span>
            <el-button size="large" @click="$router.push('/tasks')">取消</el-button>
            <el-button type="danger" size="large" @click="submitTask" :loading="submitting">
              🚀 开始扫描
            </el-button>
          </div>
        </el-card>
      </el-col>
    </el-row>
  </div>
</template>

<script setup>
import { ref, reactive } from 'vue'
import { useRouter } from 'vue-router'
import { taskApi } from '../api/tasks'
import { ElMessage } from 'element-plus'

const router = useRouter()
const formRef = ref(null)
const submitting = ref(false)

const ALL_TYPES = ['sqli', 'xss', 'file_upload', 'command_injection', 'path_traversal',
  'ssrf', 'info_disclosure', 'ssti', 'idor', 'open_redirect', 'csrf', 'nuclei']

const PRESETS = {
  top10: ['sqli', 'xss', 'command_injection', 'path_traversal', 'ssrf', 'file_upload', 'info_disclosure', 'idor', 'csrf', 'ssti'],
  injection: ['sqli', 'xss', 'command_injection', 'ssti'],
  access: ['idor', 'csrf', 'open_redirect'],
  all: [...ALL_TYPES],
}

const targets = [
  { label: 'SQLi', url: 'http://121.43.231.191:8080/targets/sqli/' },
  { label: 'XSS', url: 'http://121.43.231.191:8080/targets/xss/' },
  { label: 'Upload', url: 'http://121.43.231.191:8080/targets/upload/' },
  { label: 'CMDi', url: 'http://121.43.231.191:8080/targets/cmd/' },
  { label: 'LFI', url: 'http://121.43.231.191:8080/targets/lfi/' },
  { label: 'SSRF', url: 'http://121.43.231.191:8080/targets/ssrf/' },
  { label: 'InfoLeak', url: 'http://121.43.231.191:8080/targets/info/' },
  { label: 'SSTI', url: 'http://121.43.231.191:8080/targets/ssti/' },
  { label: 'IDOR', url: 'http://121.43.231.191:8080/targets/idor/' },
]

const form = reactive({
  target_url: '',
  scan_depth: 2,
  vuln_types: [...ALL_TYPES],
  custom_headers: '',
  custom_cookies: '',
  custom_payloads: '',
  proxy: '',
})

const rules = {
  target_url: [
    { required: true, message: '请输入目标 URL', trigger: 'blur' },
    { pattern: /^https?:\/\/.+/, message: 'URL 必须以 http:// 或 https:// 开头', trigger: 'blur' },
  ],
}

function selectAll() { form.vuln_types = [...ALL_TYPES] }
function deselectAll() { form.vuln_types = [] }
function selectPreset(key) { form.vuln_types = [...PRESETS[key]] }

async function submitTask() {
  const valid = await formRef.value.validate().catch(() => false)
  if (!valid) return
  submitting.value = true
  try {
    const data = { target_url: form.target_url, scan_depth: form.scan_depth, vuln_types: form.vuln_types }
    if (form.custom_headers.trim()) {
      try { data.custom_headers = JSON.stringify(JSON.parse(form.custom_headers)) }
      catch { ElMessage.warning('Headers JSON 格式无效'); submitting.value = false; return }
    }
    if (form.custom_cookies.trim()) {
      try { data.custom_cookies = JSON.stringify(JSON.parse(form.custom_cookies)) }
      catch { ElMessage.warning('Cookies JSON 格式无效'); submitting.value = false; return }
    }
    if (form.custom_payloads.trim()) {
      try { data.custom_payloads = JSON.stringify(JSON.parse(form.custom_payloads)) }
      catch { ElMessage.warning('Payload JSON 格式无效'); submitting.value = false; return }
    }
    if (form.proxy.trim()) data.proxy = form.proxy

    const res = await taskApi.create(data)
    ElMessage.success('扫描任务已创建！')
    router.push(`/tasks/${res.data.task.id}`)
  } catch (e) {
    ElMessage.error('创建任务失败: ' + (e.response?.data?.detail || e.message))
  }
  submitting.value = false
}
</script>

<style scoped>
.target-chips { display: flex; flex-wrap: wrap; gap: 6px; }
.target-chip { cursor: pointer; }
.vuln-group { margin-bottom: 12px; }
.vuln-group-title { font-size: 13px; color: #888; margin-bottom: 6px; padding-left: 2px; }
.vuln-group .el-checkbox { margin-right: 8px; margin-bottom: 6px; }
</style>
