import { ref, onMounted, onUnmounted } from 'vue'

/**
 * WebSocket 连接 Hook
 * 用于实时接收扫描进度推送
 */
export function useWebSocket(taskId) {
  const connected = ref(false)
  const messages = ref([])
  const latestMessage = ref(null)  // 最新消息，方便 watch 监听
  let ws = null
  let reconnectTimer = null
  let heartbeatTimer = null

  function connect() {
    const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:'
    const token = localStorage.getItem('scanner_token') || ''
    const url = `${protocol}//${location.host}/ws/tasks/${taskId}?token=${encodeURIComponent(token)}`

    ws = new WebSocket(url)

    ws.onopen = () => {
      connected.value = true
      // 心跳 (30秒一次)
      heartbeatTimer = setInterval(() => {
        if (ws && ws.readyState === WebSocket.OPEN) {
          ws.send('ping')
        }
      }, 30000)
    }

    ws.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data)
        if (msg.type !== 'pong') {
          messages.value.push(msg)
          latestMessage.value = msg  // 单独触发引用变化
        }
      } catch (e) {
        // ignore
      }
    }

    ws.onclose = () => {
      connected.value = false
      clearInterval(heartbeatTimer)
      // 自动重连
      reconnectTimer = setTimeout(connect, 3000)
    }

    ws.onerror = () => {
      connected.value = false
    }
  }

  function disconnect() {
    clearTimeout(reconnectTimer)
    clearInterval(heartbeatTimer)
    if (ws) {
      ws.close()
      ws = null
    }
  }

  onMounted(connect)
  onUnmounted(disconnect)

  return { connected, messages, latestMessage }
}
