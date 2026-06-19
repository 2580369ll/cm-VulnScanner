<template>
  <el-container style="min-height:100vh">
    <!-- 侧边栏 -->
    <el-aside width="220px" style="background:linear-gradient(180deg, #1a1a2e 0%, #16213e 100%);">
      <div style="padding:20px;text-align:center;border-bottom:1px solid #0f3460;">
        <h1 style="color:#e94560;font-size:20px;margin:0;">🛡️ VulnScanner</h1>
        <p style="color:#888;font-size:12px;margin:5px 0 0 0;">Web漏洞自动化扫描平台</p>
      </div>
      <el-menu
        :default-active="$route.path"
        background-color="transparent"
        text-color="#bbb"
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

      <div style="position:absolute;bottom:20px;width:220px;text-align:center;color:#666;font-size:12px;">
        <p>VulnScanner v1.0</p>
        <p>SQLi · XSS · FileUpload</p>
      </div>
    </el-aside>

    <!-- 主内容 -->
    <el-main style="background:#f0f2f5;padding:20px;">
      <router-view />
    </el-main>
  </el-container>
</template>

<script setup>
</script>

<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; }
</style>
