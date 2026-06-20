<template>
  <div class="task-create">
    <h2 style="margin-bottom:20px;">➕ 创建扫描任务</h2>

    <el-card>
      <el-form
        ref="formRef"
        :model="form"
        :rules="rules"
        label-width="120px"
        label-position="left"
      >
        <el-form-item label="目标 URL" prop="target_url">
          <el-input
            v-model="form.target_url"
            placeholder="输入要扫描的网址，例如 https://example.com"
            size="large"
          />
          <div style="margin-top:8px;font-size:12px;color:#999;">
            💡 测试靶场：
            <el-link type="primary" @click="form.target_url='http://121.43.231.191:8080/targets/sqli/'" :underline="false">SQLi</el-link> ·
            <el-link type="primary" @click="form.target_url='http://121.43.231.191:8080/targets/xss/'" :underline="false">XSS</el-link> ·
            <el-link type="primary" @click="form.target_url='http://121.43.231.191:8080/targets/upload/'" :underline="false">上传</el-link> ·
            <el-link type="primary" @click="form.target_url='http://121.43.231.191:8080/targets/cmd/'" :underline="false">命令注入</el-link> ·
            <el-link type="primary" @click="form.target_url='http://121.43.231.191:8080/targets/lfi/'" :underline="false">LFI</el-link> ·
            <br>
            <el-link type="primary" @click="form.target_url='http://121.43.231.191:8080/targets/ssrf/'" :underline="false">SSRF</el-link> ·
            <el-link type="primary" @click="form.target_url='http://121.43.231.191:8080/targets/info/'" :underline="false">信息泄露</el-link> ·
            <el-link type="primary" @click="form.target_url='http://121.43.231.191:8080/targets/ssti/'" :underline="false">SSTI</el-link> ·
            <el-link type="primary" @click="form.target_url='http://121.43.231.191:8080/targets/idor/'" :underline="false">IDOR</el-link>
          </div>
        </el-form-item>

        <el-form-item label="扫描深度">
          <el-slider v-model="form.scan_depth" :min="1" :max="3" show-stops :marks="{1:'浅层',2:'中等',3:'深层'}" />
        </el-form-item>

        <el-form-item label="漏洞类型">
          <el-checkbox-group v-model="form.vuln_types">
            <el-checkbox label="sqli" border size="large">🔍 SQL 注入</el-checkbox>
            <el-checkbox label="xss" border size="large">💉 XSS 跨站脚本</el-checkbox>
            <el-checkbox label="file_upload" border size="large">📁 文件上传</el-checkbox>
            <el-checkbox label="command_injection" border size="large">💻 命令注入</el-checkbox>
            <el-checkbox label="path_traversal" border size="large">📂 路径遍历</el-checkbox>
            <el-checkbox label="ssrf" border size="large">🌐 SSRF</el-checkbox>
            <el-checkbox label="info_disclosure" border size="large">🔓 信息泄露</el-checkbox>
            <el-checkbox label="ssti" border size="large">🎨 模板注入</el-checkbox>
            <el-checkbox label="idor" border size="large">🔑 越权IDOR</el-checkbox>
            <el-checkbox label="open_redirect" border size="large">↗️ 重定向</el-checkbox>
            <el-checkbox label="csrf" border size="large">🛡️ CSRF</el-checkbox>
          </el-checkbox-group>
        </el-form-item>

        <el-divider content-position="left">高级选项</el-divider>

        <el-form-item label="自定义 Cookies">
          <el-input
            v-model="form.custom_cookies"
            type="textarea"
            :rows="2"
            placeholder='{"sessionid": "abc123", "token": "xyz"}'
          />
          <span style="font-size:12px;color:#999;">JSON格式，用于登录态扫描。浏览器F12→Application→Cookies 复制</span>
        </el-form-item>

        <el-form-item label="自定义 Headers">
          <el-input
            v-model="form.custom_headers"
            type="textarea"
            :rows="2"
            placeholder='{"Authorization": "Bearer xxx", "X-Custom": "value"}'
          />
        </el-form-item>

        <el-form-item label="自定义 Payload">
          <el-input
            v-model="form.custom_payloads"
            type="textarea"
            :rows="4"
            placeholder="JSON格式，留空使用内置Payload库"
          />
          <span style="font-size:12px;color:#999;">JSON格式，key=漏洞类型，value=Payload数组。留空则使用内置Payload库</span>
        </el-form-item>

        <el-form-item label="代理">
          <el-input
            v-model="form.proxy"
            placeholder="http://127.0.0.1:8080"
          />
        </el-form-item>

        <el-form-item>
          <el-button
            type="danger"
            size="large"
            @click="submitTask"
            :loading="submitting"
            style="width:200px;"
          >
            🚀 开始扫描
          </el-button>
          <el-button size="large" @click="$router.push('/tasks')">
            取消
          </el-button>
        </el-form-item>
      </el-form>
    </el-card>
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

const form = reactive({
  target_url: '',
  scan_depth: 2,
  vuln_types: ['sqli', 'xss', 'file_upload', 'command_injection', 'path_traversal', 'ssrf', 'info_disclosure', 'ssti', 'idor', 'open_redirect', 'csrf'],
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

async function submitTask() {
  const valid = await formRef.value.validate().catch(() => false)
  if (!valid) return

  submitting.value = true
  try {
    const data = {
      target_url: form.target_url,
      scan_depth: form.scan_depth,
      vuln_types: form.vuln_types,
    }

    // 解析高级选项
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
    if (form.proxy.trim()) {
      data.proxy = form.proxy
    }

    const res = await taskApi.create(data)
    ElMessage.success('扫描任务已创建！')
    router.push(`/tasks/${res.data.task.id}`)
  } catch (e) {
    ElMessage.error('创建任务失败: ' + (e.response?.data?.detail || e.message))
  }
  submitting.value = false
}
</script>
