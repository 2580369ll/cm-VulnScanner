# 🛡️ VulnScanner — 自动化 Web 漏洞扫描平台

> 网安简历项目 | Python FastAPI + Vue 3 + Celery + SQLite + Docker

一个 **Web 管理平台 + 自动化扫描引擎**，覆盖 **7 类 Web 漏洞**的自动化检测，支持 WAF 识别与自适应绕过，内置置信度评分与去重。

**在线演示:** http://121.43.231.191:8082 | Token: 通过环境变量 `SCANNER_TOKEN` 配置

---

## ✨ 核心功能 (v2.0)

### 漏洞检测（7 类）

| 功能 | 说明 |
|------|------|
| 🔍 **SQL 注入** | Error-based / Boolean Blind / Time Blind / Union-based，自动识别 5 种数据库 |
| 💉 **XSS** | 反射型 / 存储型 / DOM-based，3 级 Payload 库 + 自动变异绕过 |
| 📁 **文件上传** | 14 种绕过 Payload：扩展名/Content-Type/魔法字节/图片马/条件竞争 |
| 💻 **命令注入** | Time-based + Output-based + Error-based，覆盖 Linux/Windows |
| 📂 **路径遍历/LFI** | Linux/Windows 路径 + 编码绕过 + PHP 封装器检测 |
| 🌐 **SSRF** | 云元数据 / 内网服务探测 / 协议走私 / IP 绕过变体 |
| 🔓 **信息泄露** | 200+ 敏感路径：.git/.env/备份文件/Swagger/Actuator/phpinfo |

### 引擎特性

| 功能 | 说明 |
|------|------|
| 🛡️ **WAF 识别** | 自动检测阿里云WAF/Cloudflare/安全狗/长亭雷池/ModSecurity |
| 🔧 **WAF 绕过** | 统一绕过引擎：7 编码器 + 9 Tamper + 链式绕过 |
| 📊 **置信度评分** | 每个漏洞 0-1 置信度，自动去重保留最高分 |
| 🔌 **插件架构** | 继承 BasePlugin 即可扩展，自动注册到引擎 |
| 🔐 **Token 认证** | Bearer Token + 登录页 + 路由守卫 |
| 🚫 **任务取消** | Redis 信号机制，运行中任务可随时取消 |

### Web 管理平台

| 功能 | 说明 |
|------|------|
| 📊 **仪表盘** | ECharts 可视化统计，漏洞类型/严重度分布 |
| 📋 **任务管理** | 创建/列表/详情/删除，7 种漏洞类型可选 |
| ⚡ **实时进度** | WebSocket 推送扫描进度，漏洞实时展示 |
| 📄 **报告导出** | JSON/HTML 格式，含完整 PoC 和修复建议 |
| 🎯 **内置靶场** | 7 个 PHP 漏洞靶场用于自测验证 |
| 🐳 **一键部署** | Docker Compose 5 服务编排，10 分钟上线 |

---

## 🏗️ 技术架构

```
Nginx → Vue 3 (前端) + FastAPI (后端) → Redis + PostgreSQL
                                     → Celery Worker (扫描引擎)
```

- **后端框架:** FastAPI (异步) + Celery (异步任务)
- **前端:** Vue 3 + Element Plus + ECharts
- **数据库:** PostgreSQL + Redis
- **扫描引擎:** httpx (异步HTTP) + BeautifulSoup
- **容器化:** Docker Compose

---

## 🚀 快速启动

### 前置要求

- Docker & Docker Compose
- 至少 4GB 可用内存

### 启动

```bash
# 1. 克隆项目
cd vuln-scanner

# 2. 一键启动所有服务
docker-compose up -d

# 3. 等待服务就绪后访问
# 前端: http://localhost
# API 文档: http://localhost:8000/docs
# 靶场: http://localhost:8080/targets/sqli/
```

### 测试扫描器

1. 访问前端 `http://localhost`
2. 点击「创建任务」
3. 输入靶场 URL: `http://targets:80/targets/sqli/`
4. 勾选 SQL注入，点击「开始扫描」
5. 查看实时扫描进度和结果

---

## 📂 项目结构

```
vuln-scanner/
├── docker-compose.yml          # 一键部署编排
├── backend/
│   ├── app/
│   │   ├── main.py             # FastAPI 入口
│   │   ├── config.py           # 配置管理
│   │   ├── api/                # REST API + WebSocket
│   │   ├── models/             # SQLAlchemy 模型
│   │   ├── scanner/            # ★ 扫描引擎
│   │   │   ├── engine.py       # 调度引擎
│   │   │   ├── crawler.py      # 爬虫
│   │   │   ├── waf_detector.py # WAF检测
│   │   │   ├── plugins/        # 漏洞插件
│   │   │   │   ├── sqli.py     # SQL注入检测
│   │   │   │   ├── xss.py      # XSS检测
│   │   │   │   └── file_upload.py # 文件上传检测
│   │   │   ├── payloads/       # Payload库
│   │   │   └── bypass/         # WAF绕过
│   │   ├── tasks/              # Celery 异步任务
│   │   └── utils/              # 工具(报告生成等)
│   └── requirements.txt
├── frontend/                   # Vue 3 前端
│   └── src/
│       ├── views/              # 页面
│       │   ├── Dashboard.vue   # 仪表盘
│       │   ├── TaskCreate.vue  # 创建任务
│       │   ├── TaskDetail.vue  # 任务详情(实时进度)
│       │   └── VulnDetail.vue  # 漏洞详情
│       └── components/         # 通用组件
├── targets/                    # 漏洞靶场
│   ├── sqli/index.php          # SQL注入靶场
│   ├── xss/index.php           # XSS靶场
│   └── upload/index.php        # 文件上传靶场
└── nginx/                      # Nginx 配置
```

---

## 🧪 漏洞靶场

项目内置 3 个 PHP 漏洞靶场用于测试：

| 靶场 | 地址 | 注入点 |
|------|------|--------|
| SQL 注入 | `/targets/sqli/` | GET search(Error-based) + POST login(Boolean盲注) + GET id(Time/Union) |
| XSS | `/targets/xss/` | GET q(反射型) + 留言板(存储型) + URL hash(DOM-based) |
| 文件上传 | `/targets/upload/` | 无过滤/Content-Type/扩展名黑名单/魔数校验 |

---

## 🔧 插件扩展

扫描器支持插件化扩展。添加新漏洞类型只需 3 步：

1. 在 `backend/app/scanner/payloads/` 添加 Payload 库
2. 继承 `BasePlugin` 实现 `check()` 方法
3. 在 `engine.py` 的 `plugin_map` 注册

```python
# 示例: 添加 SSRF 插件
class SSRFPlugin(BasePlugin):
    name = "ssrf"
    vuln_type = "ssrf"

    async def check(self, ip: InjectionPoint) -> list[Finding]:
        # 检测逻辑...
        pass
```

---

## 📝 待做功能

- [ ] 命令注入检测插件
- [ ] SSRF 检测插件
- [ ] 越权 (IDOR/BAC) 检测插件
- [ ] 用户认证系统
- [ ] 定时扫描任务
- [ ] 邮件/钉钉告警通知

---

## ⚠️ 免责声明

本工具仅供**授权的安全测试**和**学习研究**使用。使用者应遵守相关法律法规，在获得明确授权后方可对目标进行扫描。作者不对任何未授权使用导致的后果负责。

---

## 📄 License

MIT License
