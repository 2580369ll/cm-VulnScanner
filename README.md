# 🛡️ VulnScanner — 自动化 Web 漏洞扫描平台

> 网安简历项目 | Python FastAPI + Vue 3 + Celery + SQLite + Docker

**11 种 Web 漏洞**自动化检测平台。支持 WAF 识别与自适应绕过、JWT 认证、WebSocket 实时进度、置信度评分与去重、报告导出。

**在线演示:** http://121.43.231.191:8082 | 初始Token: `vulnscanner2024`

---

## ✨ 核心功能

### 漏洞检测（11 类）

| 类型 | 检测方法 |
|------|---------|
| 🔍 **SQL 注入** | Error / Boolean Blind / Time Blind / Union-based，双确认验证，5种数据库指纹 |
| 💉 **XSS** | 反射型 / 存储型 / DOM-based，3级Payload库自动变异绕过 |
| 📁 **文件上传** | 14种绕过：扩展名/Content-Type/魔法字节/图片马/条件竞争/.htaccess |
| 💻 **命令注入** | Time + Output + Error-based，Linux/Windows 双平台 |
| 📂 **路径遍历** | Linux/Windows路径 + 编码绕过 + PHP封装器 |
| 🌐 **SSRF** | 云元数据 / 内网探测 / 协议走私 / IP绕过变体 |
| 🔓 **信息泄露** | 200+敏感路径：.git/.env/备份/Swagger/Actuator/phpinfo |
| 🎨 **SSTI** | 6引擎（Jinja2/Twig/Freemarker/Velocity/Mako/Pug），`{{7*7}}`→`{{8*8}}`双确认 |
| 🔑 **IDOR** | 111条API端点枚举 + PII数据分析 |
| ↗️ **Open Redirect** | 跳转参数检测 + Location头分析 |
| 🛡️ **CSRF** | Token缺失 + SameSite + 跨域Origin校验 |

### 引擎特性

| 功能 | 说明 |
|------|------|
| 🛡️ **WAF识别+绕过** | 6种WAF特征库 → 7编码器+9Tamper统一绕过引擎 |
| ✅ **双确认验证** | Error+Boolean交叉验证，置信度最高0.98 |
| 📊 **置信度评分** | 每漏洞0-1置信度，自动去重保留最高分 |
| 🌐 **登录态扫描** | 支持Cookie注入，扫描需认证的页面 |
| 🗺️ **智能爬虫** | sitemap.xml + robots.txt解析，Header/Cookie注入点发现 |
| ✏️ **自定义Payload** | JSON格式注入自定义Payload，与内置库混合使用 |
| 🔌 **插件架构** | 继承`BasePlugin`即可扩展，自动注册到引擎 |

### Web 管理平台

| 功能 | 说明 |
|------|------|
| 🔐 **JWT认证** | 登录页 + 路由守卫 + Axios拦截器 + 全局错误处理 |
| 📊 **仪表盘** | ECharts可视化，漏洞类型/严重度饼图 |
| ⚡ **实时进度** | WebSocket推送 + 指数退避重连 + Token鉴权 |
| 🔍 **漏洞筛选** | 按严重度/类型/关键词筛选，一键导出JSON/HTML报告 |
| 🌓 **暗色模式** | 一键切换，localStorage持久化 |
| 🎯 **9个内置靶场** | PHP漏洞靶场，一键填入URL测试 |
| 🐳 **Docker部署** | 5服务编排，10分钟上线 |

---

## 🏗️ 技术架构

```
                    ┌─────────────┐
                    │   Nginx:80  │
                    └──────┬──────┘
                           │
            ┌──────────────┼──────────────┐
            ▼              ▼              ▼
     ┌──────────┐   ┌──────────┐   ┌──────────┐
     │  Vue 3   │   │ FastAPI  │   │  PHP     │
     │  (静态)   │   │  :8000   │   │ Targets  │
     └──────────┘   └────┬─────┘   └──────────┘
                         │
            ┌────────────┼────────────┐
            ▼            ▼            ▼
     ┌──────────┐ ┌──────────┐ ┌──────────┐
     │  Celery  │ │  Redis   │ │ SQLite   │
     │  Worker  │ │  缓存/队列│ │  数据库  │
     └──────────┘ └──────────┘ └──────────┘
```

| 层级 | 技术 |
|------|------|
| 前端 | Vue 3.5 + Element Plus + ECharts + VueUse |
| 后端 | FastAPI + Celery + slowapi |
| 扫描 | httpx(异步) + BeautifulSoup + 11插件 |
| 存储 | SQLite + Redis |
| 认证 | JWT (HS256, 24h过期) |
| 部署 | Docker Compose |

---

## 🚀 快速启动

```bash
git clone https://github.com/2580369ll/cm-VulnScanner.git
cd cm-VulnScanner
cp .env.example .env
docker compose -f docker-compose.prod.yml up -d
```

访问: http://localhost:8082 | 登录Token: `vulnscanner2024`

---

## 🧪 内置靶场

| 靶场 | 测试漏洞 |
|------|---------|
| `/targets/sqli/` | SQL注入 (Error/Boolean/Time/Union) |
| `/targets/xss/` | XSS (反射/存储/DOM) |
| `/targets/upload/` | 文件上传 (4种安全等级) |
| `/targets/cmd/` | 命令注入 (直接执行+命令拼接) |
| `/targets/lfi/` | 路径遍历 (include+file_get_contents) |
| `/targets/ssrf/` | SSRF (file_get_contents+curl) |
| `/targets/info/` | 信息泄露 (.git/.env/Swagger) |
| `/targets/ssti/` | SSTI (Twig/Freemarker/Mako) |
| `/targets/idor/` | IDOR (用户/订单/发票API) |

---

## 📂 项目结构

```
vuln-scanner/
├── backend/app/
│   ├── main.py                 # FastAPI入口+JWT登录
│   ├── auth.py                 # JWT认证中间件
│   ├── api/                    # REST + WebSocket
│   ├── models/                 # SQLAlchemy模型
│   ├── scanner/
│   │   ├── engine.py           # 扫描调度引擎
│   │   ├── crawler.py          # 爬虫(sitemap/robots)
│   │   ├── waf_detector.py     # WAF识别
│   │   ├── plugins/            # 11个检测插件
│   │   ├── payloads/           # 11个Payload库
│   │   └── bypass/             # 绕过引擎(编码器+Tamper)
│   ├── tasks/                  # Celery异步任务
│   └── utils/                  # CVSS/CWE/报告/日志
├── frontend/src/
│   ├── views/                  # 6个页面组件
│   ├── components/             # 4个通用组件
│   └── api/                    # Axios+WebSocket
├── targets/                    # 9个PHP靶场
├── nginx/                      # Nginx配置
└── docker-compose.prod.yml     # 生产部署
```

---

## 📊 版本演进

| 版本 | 新增 |
|------|------|
| v1.0 | SQLi + XSS + FileUpload，Web平台，WAF绕过 |
| v2.0 | +命令注入/路径遍历/SSRF/信息泄露，爬虫增强，置信度评分 |
| v2.1 | JWT认证，PDF导出，单元测试，限流，暗色模式 |
| v2.2 | +SSTI/IDOR/OpenRedirect/CSRF，双确认验证，CVSS/CWE |
| v2.3 | Cookie登录态，sitemap爬虫，自定义Payload，靶场快捷链接 |
| v3.0 | 认证加固(路由守卫+拦截器)，漏洞筛选/导出，WebSocket退避重连 |

---

## ⚠️ 免责声明

本工具仅供**授权的安全测试**和**学习研究**使用。使用者应遵守相关法律法规。

---

## 📄 License

MIT License
