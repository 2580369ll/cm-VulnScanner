<template>
  <div class="login-page">
    <el-card class="login-card">
      <div style="text-align:center;margin-bottom:25px;">
        <h1 style="color:#e94560;font-size:28px;">🛡️ VulnScanner</h1>
        <p style="color:#999;">Web 漏洞自动化扫描平台</p>
      </div>

      <el-form @submit.prevent="doLogin">
        <el-form-item>
          <el-input
            v-model="token"
            placeholder="请输入访问 Token"
            size="large"
            type="password"
            show-password
            @keyup.enter="doLogin"
          />
        </el-form-item>
        <el-form-item>
          <el-button
            type="danger"
            size="large"
            style="width:100%;"
            :loading="loading"
            @click="doLogin"
          >
            🔐 登录
          </el-button>
        </el-form-item>
      </el-form>

      <p v-if="error" style="color:#e94560;text-align:center;">{{ error }}</p>
      <p style="color:#999;font-size:12px;text-align:center;">
        默认 Token: <code>vulnscanner2024</code>
      </p>
    </el-card>
  </div>
</template>

<script setup>
import { ref } from 'vue'
import { useRouter } from 'vue-router'
import axios from 'axios'

const router = useRouter()
const token = ref('')
const loading = ref(false)
const error = ref('')

async function doLogin() {
  if (!token.value.trim()) {
    error.value = '请输入 Token'
    return
  }

  loading.value = true
  error.value = ''

  try {
    const res = await axios.post('/api/auth/login', { token: token.value })
    if (res.data.success) {
      localStorage.setItem('scanner_token', res.data.token)
      router.push('/')
    } else {
      error.value = 'Token 无效'
    }
  } catch (e) {
    error.value = '登录失败: ' + (e.response?.data?.detail || e.message)
  }
  loading.value = false
}
</script>

<style scoped>
.login-page {
  display: flex;
  align-items: center;
  justify-content: center;
  min-height: 100vh;
  background: linear-gradient(135deg, #1a1a2e, #16213e);
}
.login-card {
  width: 400px;
  padding: 30px;
  border-radius: 12px;
}
code { background: #f0f0f0; padding: 2px 6px; border-radius: 3px; }
</style>
