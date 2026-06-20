import { ref, onMounted, onUnmounted } from 'vue'

/**
 * WebSocket 连接 Hook — 指数退避重连 + Token 鉴权
 */
export function useWebSocket(taskId) {
  const connected = ref(false)
  const messages = ref([])
  const latestMessage = ref(null)
  let ws = null
  let reconnectTimer = null
  let heartbeatTimer = null
  let attempt = 0

  function connect() {
    const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:'
    const token = localStorage.getItem('scanner_token') || ''
    const url = `${protocol}//${location.host}/ws/tasks/${taskId}?token=${encodeURIComponent(token)}`

    ws = new WebSocket(url)

    ws.onopen = () => {
      connected.value = true
      attempt = 0  // 重置退避计数
      heartbeatTimer = setInterval(() => {
        if (ws && ws.readyState === WebSocket.OPEN) {
          ws.send('ping')
        }
      }, 15000)  // 15秒心跳
    }

    ws.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data)
        if (msg.type !== 'pong') {
          messages.value.push(msg)
          latestMessage.value = msg
        }
      } catch (e) {
        // ignore
      }
    }

    ws.onclose = () => {
      connected.value = false
      clearInterval(heartbeatTimer)
      // 指数退避重连: 1s, 2s, 4s, 8s, 16s, 30s(max)
      const delay = Math.min(1000 * Math.pow(2, attempt), 30000)
      attempt++
      reconnectTimer = setTimeout(connect, delay)
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
