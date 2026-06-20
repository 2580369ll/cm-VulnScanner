import axios from 'axios'
import { ElMessage } from 'element-plus'

const api = axios.create({
  baseURL: '/api',
  timeout: 15000,
})

// 请求拦截器：自动附加 JWT Token
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('scanner_token')
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

// 响应拦截器：全局错误处理
api.interceptors.response.use(
  (res) => res,
  (err) => {
    const status = err.response?.status
    if (status === 401 || status === 403) {
      localStorage.removeItem('scanner_token')
      ElMessage.error('认证已过期，请重新登录')
      if (window.location.pathname !== '/login') {
        window.location.href = '/login'
      }
    } else if (status === 429) {
      ElMessage.warning('请求过于频繁，请稍后重试')
    } else if (status === 500) {
      ElMessage.error('服务器内部错误')
    } else if (!err.response) {
      ElMessage.error('网络连接失败，请检查网络')
    }
    return Promise.reject(err)
  }
)

// 任务相关
export const taskApi = {
  create(data) {
    return api.post('/tasks', data)
  },
  list(page = 1, pageSize = 20) {
    return api.get('/tasks', { params: { page, page_size: pageSize } })
  },
  get(id) {
    return api.get(`/tasks/${id}`)
  },
  delete(id) {
    return api.delete(`/tasks/${id}`)
  },
  cancel(id) {
    return api.post(`/tasks/${id}/cancel`)
  },
  stats() {
    return api.get('/stats')
  },
}

// 结果相关
export const resultApi = {
  listByTask(taskId) {
    return api.get(`/tasks/${taskId}/results`)
  },
  get(id) {
    return api.get(`/results/${id}`)
  },
}

// 认证相关
export const authApi = {
  login(token) {
    return axios.post('/api/auth/login', { token })
  },
}

export default api
