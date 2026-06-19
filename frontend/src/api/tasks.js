import axios from 'axios'

const api = axios.create({
  baseURL: '/api',
  timeout: 15000,
})

// 请求拦截器：自动附加 Token
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('scanner_token')
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

// 响应拦截器：401 时跳转到登录页
api.interceptors.response.use(
  (res) => res,
  (err) => {
    if (err.response?.status === 401 || err.response?.status === 403) {
      localStorage.removeItem('scanner_token')
      if (window.location.pathname !== '/login') {
        window.location.href = '/login'
      }
    }
    return Promise.reject(err)
  }
)

// 任务相关
export const taskApi = {
  // 创建扫描任务
  create(data) {
    return api.post('/tasks', data)
  },
  // 获取任务列表
  list(page = 1, pageSize = 20) {
    return api.get('/tasks', { params: { page, page_size: pageSize } })
  },
  // 获取任务详情
  get(id) {
    return api.get(`/tasks/${id}`)
  },
  // 删除任务
  delete(id) {
    return api.delete(`/tasks/${id}`)
  },
  // 获取统计数据
  stats() {
    return api.get('/stats')
  },
}

// 结果相关
export const resultApi = {
  // 获取任务的所有漏洞
  listByTask(taskId) {
    return api.get(`/tasks/${taskId}/results`)
  },
  // 获取漏洞详情
  get(id) {
    return api.get(`/results/${id}`)
  },
}

export default api
