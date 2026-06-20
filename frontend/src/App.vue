<template>
  <div :class="{ dark: isDark }">
    <el-container style="min-height:100vh">
      <el-aside width="220px" class="sidebar">
        <div class="logo-area">
          <h1>🛡️ VulnScanner</h1>
          <p>Web漏洞自动化扫描平台</p>
        </div>
        <el-menu
          :default-active="$route.path"
          background-color="transparent"
          :text-color="isDark ? '#bbb' : '#555'"
          active-text-color="#e94560"
          router
          style="border:none;"
        >
          <el-menu-item index="/">
            <el-icon><DataAnalysis /></el-icon>
            <span>仪表盘</span>
          </el-menu-item>
          <el-menu-item index="/tasks/create">
            <el-icon><Plus /></el-icon>
            <span>创建任务</span>
          </el-menu-item>
          <el-menu-item index="/tasks">
            <el-icon><List /></el-icon>
            <span>任务列表</span>
          </el-menu-item>
        </el-menu>

        <div class="sidebar-footer">
          <el-button circle @click="toggleDark()" size="small">
            {{ isDark ? '☀️' : '🌙' }}
          </el-button>
          <p>VulnScanner v2.0</p>
          <p>11种漏洞检测</p>
        </div>
      </el-aside>

      <el-main :style="{ background: isDark ? '#1a1a2e' : '#f0f2f5' }">
        <router-view />
      </el-main>
    </el-container>
  </div>
</template>

<script setup>
import { useDark, useToggle } from '@vueuse/core'

const isDark = useDark({ storageKey: 'vulnscanner-dark-mode' })
const toggleDark = useToggle(isDark)
</script>

<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; }
.sidebar { background: linear-gradient(180deg, #1a1a2e 0%, #16213e 100%); }
.dark .sidebar { background: linear-gradient(180deg, #0d0d1a 0%, #1a1a2e 100%); }
.logo-area { padding: 20px; text-align: center; border-bottom: 1px solid #0f3460; }
.logo-area h1 { color: #e94560; font-size: 20px; margin: 0; }
.logo-area p { color: #888; font-size: 12px; margin: 5px 0 0 0; }
.sidebar-footer { position: absolute; bottom: 20px; width: 220px; text-align: center; color: #666; font-size: 12px; }
.sidebar-footer p { margin: 3px 0; }
.sidebar-footer .el-button { margin-bottom: 8px; }
.dark body { background: #0d0d1a; color: #eee; }
.dark .el-card { background: #16213e; border-color: #0f3460; color: #eee; }
.dark .el-card__header { color: #53a8b6; }
.dark h2 { color: #eee !important; }
.dark .stat-info h3 { color: #eee !important; }
</style>
