"""信息泄露 Payload 库 — 敏感路径和文件探测

覆盖分类:
1. 版本控制文件 (.git / .svn / .hg)
2. 环境配置文件 (.env / .env.local / .env.production)
3. 备份文件 (.bak / .old / .swp / ~)
4. 框架配置文件 (web.xml / wp-config.php / database.yml / application.properties)
5. 调试端点 (phpinfo / server-status / actuator / trace.axd)
6. 日志文件 (error.log / debug.log / access.log)
7. 编辑器/IDE 配置 (.vscode / .idea / .DS_Store)
"""

# ========== 版本控制文件 ==========
VERSION_CONTROL_PATHS = [
    # Git
    "/.git/config",
    "/.git/HEAD",
    "/.git/index",
    "/.git/description",
    "/.git/logs/HEAD",
    "/.git/refs/heads/master",
    "/.git/refs/heads/main",
    "/.git/packed-refs",
    "/.git/COMMIT_EDITMSG",
    "/.gitignore",
    # SVN
    "/.svn/entries",
    "/.svn/wc.db",
    "/.svn/format",
    "/.svnignore",
    # Mercurial
    "/.hg/store",
    "/.hg/requires",
    "/.hg/hgrc",
    "/.hgignore",
    # Bazaar
    "/.bzr/README",
    "/.bzrignore",
    # CVS
    "/CVS/Entries",
    "/CVS/Root",
]

# ========== 环境配置文件 ==========
ENV_FILE_PATHS = [
    "/.env",
    "/.env.local",
    "/.env.production",
    "/.env.development",
    "/.env.staging",
    "/.env.backup",
    "/.env.example",
    "/.env.old",
    "/.env.save",
    "/config/.env",
    "/config/.env.local",
    "/config/.env.production",
    "/backend/.env",
    "/server/.env",
    "/app/.env",
    "/api/.env",
    "/admin/.env",
    "/core/.env",
    "/www/.env",
    "/html/.env",
    "/public/.env",
    ".env",
]

# ========== 备份文件 ==========
BACKUP_PATHS = [
    # PHP 备份
    "/index.php.bak",
    "/index.php~",
    "/index.php.old",
    "/index.php.orig",
    "/index.php.swp",
    "/index.php.save",
    "/index.php.backup",
    "/index.php.bk",
    "/index.phps",
    # 配置文件备份
    "/config.php.bak",
    "/config.php~",
    "/config.php.old",
    "/config.php.orig",
    "/config.php.swp",
    "/config.php.save",
    # ASP.NET 备份
    "/web.config.bak",
    "/web.config~",
    "/web.config.old",
    "/web.config.orig",
    # 数据库备份
    "/database.sql",
    "/database.sql.gz",
    "/database.sql.bak",
    "/db.sql",
    "/dump.sql",
    "/backup.sql",
    "/data.sql",
    "/export.sql",
    "/db_backup.sql",
    "/mysql.sql",
    "/postgres.sql",
    "/dump.tar.gz",
    "/db.tar.gz",
    # 其他常见备份
    "/site.tar.gz",
    "/site.zip",
    "/wwwroot.zip",
    "/backup.zip",
    "/backup.tar.gz",
    "/wp-content/backup/",
    "/uploads/backup/",
    # 编辑器临时文件
    "/index.html~",
    "/login.php~",
    "/admin.php~",
    # 特定应用备份
    "/wp-config.php.bak",
    "/wp-config.php~",
    "/wp-config.php.old",
    "/wp-config.php.orig",
]

# ========== 框架/应用配置文件 ==========
CONFIG_FILE_PATHS = [
    # Java / JSP
    "/WEB-INF/web.xml",
    "/WEB-INF/classes/application.properties",
    "/WEB-INF/classes/application.yml",
    "/WEB-INF/classes/hibernate.cfg.xml",
    "/WEB-INF/classes/log4j.properties",
    "/WEB-INF/classes/jdbc.properties",
    "/WEB-INF/classes/db.properties",
    "/WEB-INF/applicationContext.xml",
    "/WEB-INF/struts.xml",
    # Spring Boot
    "/actuator",
    "/actuator/health",
    "/actuator/info",
    "/actuator/env",
    "/actuator/configprops",
    "/actuator/mappings",
    "/actuator/beans",
    "/actuator/conditions",
    "/actuator/loggers",
    "/actuator/metrics",
    "/actuator/heapdump",
    "/actuator/threaddump",
    "/actuator/gateway/routes",
    "/actuator/scheduledtasks",
    # WordPress
    "/wp-config.php",
    "/wp-admin/install.php",
    "/wp-login.php",
    "/wp-json/wp/v2/users",
    "/xmlrpc.php",
    # Ruby on Rails
    "/config/database.yml",
    "/config/secrets.yml",
    "/config/credentials.yml.enc",
    "/config/master.key",
    "/config/storage.yml",
    "/config/environments/production.rb",
    # Django
    "/settings.py",
    "/config/settings.py",
    "/app/settings.py",
    "/requirements.txt",
    # Laravel
    "/.env",
    "/storage/logs/laravel.log",
    "/storage/logs/laravel-",
    "/artisan",
    # Node.js
    "/package.json",
    "/package-lock.json",
    "/yarn.lock",
    "/.npmrc",
    "/node_modules/.package-lock.json",
    # Python
    "/requirements.txt",
    "/Pipfile",
    "/Pipfile.lock",
    "/setup.py",
    "/setup.cfg",
    "/pyproject.toml",
    # Go
    "/go.mod",
    "/go.sum",
    # Other
    "/Gemfile",
    "/Gemfile.lock",
    "/composer.json",
    "/composer.lock",
    "/Dockerfile",
    "/docker-compose.yml",
    "/docker-compose.yaml",
    "/.dockerignore",
    "/Makefile",
    "/Procfile",
    "/.htaccess",
    "/robots.txt",
    "/sitemap.xml",
    "/crossdomain.xml",
    "/clientaccesspolicy.xml",
    "/security.txt",
    "/.well-known/security.txt",
]

# ========== 调试/信息端点 ==========
DEBUG_PATHS = [
    # PHP 信息
    "/phpinfo.php",
    "/info.php",
    "/test.php",
    "/php_info.php",
    "/phpversion.php",
    "/phpinfo",
    "/info",
    # Apache 状态
    "/server-status",
    "/server-info",
    "/server-status?auto",
    # IIS
    "/trace.axd",
    "/trace.axd?detail=1",
    # 调试页面
    "/debug",
    "/debug/default",
    "/debug/default/view",
    "/test",
    "/testing",
    "/dev",
    "/development",
    # 管理面板
    "/admin",
    "/admin/",
    "/admin/index.php",
    "/admin/login.php",
    "/admin/login",
    "/adminer.php",
    "/admin.php",
    "/manage",
    "/manager",
    "/management",
    # 数据库管理
    "/phpmyadmin/",
    "/phpMyAdmin/",
    "/pma/",
    "/myadmin/",
    "/mysql/",
    "/db/",
    "/dbadmin/",
    "/sql/",
    # API 文档
    "/swagger",
    "/swagger-ui.html",
    "/swagger/index.html",
    "/api-docs",
    "/api/docs",
    "/api/swagger",
    "/api/v1/docs",
    "/api/v2/docs",
    "/v2/api-docs",
    "/v3/api-docs",
    "/openapi.json",
    "/openapi.yaml",
    "/graphql",
    "/graphiql",
    "/playground",
    # 监控端点
    "/metrics",
    "/health",
    "/status",
    "/healthcheck",
    "/health-check",
    "/ping",
    "/ready",
    "/live",
    # 运维工具
    "/jenkins/",
    "/jenkins/login",
    "/solr/",
    "/solr/admin/",
    "/nacos/",
    "/druid/",
    "/druid/index.html",
    "/druid/websession.html",
    "/env",
    "/console",
    "/jmx-console",
    "/web-console",
    "/jmx",
    "/_status",
    "/_health",
]

# ========== 日志文件 ==========
LOG_FILE_PATHS = [
    "/error.log",
    "/error_log",
    "/errors.log",
    "/debug.log",
    "/debug_log",
    "/access.log",
    "/access_log",
    "/app.log",
    "/application.log",
    "/server.log",
    "/php_errors.log",
    "/php_error.log",
    "/mysql.log",
    "/mysql_error.log",
    "/database.log",
    "/sql.log",
    "/query.log",
    "/slow.log",
    "/log.txt",
    "/logs/error.log",
    "/logs/debug.log",
    "/logs/access.log",
    "/logs/app.log",
    "/logs/application.log",
    "/logs/production.log",
    "/logs/development.log",
    "/logs/laravel.log",
    "/storage/logs/laravel.log",
    "/runtime/logs/",
    "/var/log/",
    "/tmp/log/",
    # Windows
    "/App_Data/Logs/",
    "/logs/error.txt",
    "/logs/access.txt",
]

# ========== 编辑器/IDE 配置文件 ==========
EDITOR_CONFIG_PATHS = [
    # VS Code
    "/.vscode/",
    "/.vscode/settings.json",
    "/.vscode/launch.json",
    "/.vscode/tasks.json",
    "/.vscode/extensions.json",
    # JetBrains
    "/.idea/",
    "/.idea/workspace.xml",
    "/.idea/modules.xml",
    "/.idea/vcs.xml",
    "/.idea/.name",
    # macOS
    "/.DS_Store",
    # Sublime Text
    "/*.sublime-project",
    "/*.sublime-workspace",
    # Vim
    "/.vimrc",
    "/.viminfo",
    # Emacs
    "/.emacs",
    "/.emacs.d/",
    # Eclipse
    "/.project",
    "/.classpath",
    "/.settings/",
    # NetBeans
    "/nbproject/",
    "/nbproject/project.xml",
]

# ========== 响应内容检测模式 ==========
CONTENT_DETECTION_PATTERNS = {
    "env_file": [
        # 数据库凭据
        "DB_HOST",
        "DB_PASSWORD",
        "DB_USERNAME",
        "DB_DATABASE",
        "DB_PORT",
        "DATABASE_URL",
        "MYSQL_ROOT_PASSWORD",
        # API 密钥
        "API_KEY",
        "APP_KEY",
        "API_SECRET",
        "API_TOKEN",
        "SECRET_KEY",
        "SECRET",
        "ACCESS_KEY",
        "ACCESS_SECRET",
        "SECRET_ACCESS_KEY",
        # Redis
        "REDIS_URL",
        "REDIS_HOST",
        "REDIS_PASSWORD",
        "REDIS_PORT",
        # JWT/认证
        "JWT_SECRET",
        "JWT_KEY",
        "JWT_TOKEN",
        "APP_SECRET",
        "ENCRYPTION_KEY",
        # SMTP
        "MAIL_HOST",
        "MAIL_USERNAME",
        "MAIL_PASSWORD",
        "SMTP_PASSWORD",
        "MAIL_FROM_ADDRESS",
        # 云凭据
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "ALIBABA_CLOUD_ACCESS_KEY",
        "TENCENT_SECRET_ID",
        "GCP_CREDENTIALS",
        "AZURE_CLIENT_SECRET",
        # 其他
        "PASSWORD",
        "TOKEN",
        "PRIVATE_KEY",
    ],
    "git_config": [
        "[core]",
        "[remote",
        "[branch",
        "repositoryformatversion",
        "bare",
        "url = ",
        "fetch = ",
        "origin",
    ],
    "php_info": [
        "PHP Version",
        "phpinfo()",
        "Server API",
        "Virtual Directory Support",
        "Configuration File (php.ini)",
        "Loaded Configuration File",
        "PHP Extension",
        "PHP License",
        "PHP Version =>",
        "System =>",
        "Build Date =>",
        "Configure Command =>",
        "Server Root",
    ],
    "spring_actuator": [
        "spring-boot",
        '"status":"UP"',
        '"status":"DOWN"',
        '"status":"UNKNOWN"',
        '"groups":',
        '"health"',
        "spring-boot-starter-actuator",
        "_links",
        "self",
        "mappings",
        "beans",
        "env",
        "metrics",
        "configprops",
        "threaddump",
        "heapdump",
        "loggers",
        "info",
        "health",
    ],
    "apache_status": [
        "Server Version:",
        "Server MPM:",
        "Server Built:",
        "Current Time:",
        "Restart Time:",
        "Parent Server Config. Generation:",
        "Server uptime:",
        "Total accesses:",
    ],
    "swagger": [
        "swagger",
        '"openapi"',
        "Swagger UI",
        "swagger-ui",
        "api-docs",
        "ApiDocumentation",
    ],
    "laravel_log": [
        "laravel.log",
        "Stack trace:",
        "PDOException",
        "QueryException",
        "ErrorException",
    ],
    "dotnet_trace": [
        "trace.axd",
        "Application Trace",
        "Request Details",
        "Trace Information",
        "Request Trace",
    ],
    "wordpress_config": [
        "DB_NAME",
        "DB_USER",
        "DB_PASSWORD",
        "DB_HOST",
        "define(",
        "AUTH_KEY",
        "SECURE_AUTH_KEY",
        "LOGGED_IN_KEY",
        "NONCE_KEY",
        "AUTH_SALT",
        "table_prefix",
    ],
    "settings_file": [
        "DATABASES",
        "SECRET_KEY",
        "DEBUG =",
        "ALLOWED_HOSTS",
        "INSTALLED_APPS",
        "MIDDLEWARE",
    ],
}


def get_info_paths() -> list[dict]:
    """获取所有信息泄露探测路径

    Returns:
        列表，每个元素为 {
            "path": str,           # 请求路径
            "category": str,       # 分类: version_control / env / backup / config / debug / log / editor
            "method": str,         # 请求方法 (HEAD / GET)
            "check_content": bool, # 是否需要检查响应内容
            "content_patterns": str | None  # 匹配模式组名称
        }
    """
    paths = []

    # 版本控制文件
    for p in VERSION_CONTROL_PATHS:
        paths.append({
            "path": p,
            "category": "version_control",
            "method": "HEAD",
            "check_content": True,
            "content_patterns": "git_config" if ".git/" in p else "git_config"
                           if ".svn/" in p or ".hg/" in p else None,
        })

    # 环境配置
    for p in ENV_FILE_PATHS:
        paths.append({
            "path": p,
            "category": "env",
            "method": "HEAD",
            "check_content": True,
            "content_patterns": "env_file",
        })

    # 备份文件
    for p in BACKUP_PATHS:
        paths.append({
            "path": p,
            "category": "backup",
            "method": "HEAD",
            "check_content": True,
            "content_patterns": _guess_content_pattern(p),
        })

    # 配置文件
    for p in CONFIG_FILE_PATHS:
        paths.append({
            "path": p,
            "category": "config",
            "method": "HEAD",
            "check_content": not p.startswith("/actuator"),
            "content_patterns": _guess_content_pattern(p),
        })

    # 调试端点
    for p in DEBUG_PATHS:
        paths.append({
            "path": p,
            "category": "debug",
            "method": "HEAD",
            "check_content": True,
            "content_patterns": _guess_content_pattern(p),
        })

    # 日志文件
    for p in LOG_FILE_PATHS:
        paths.append({
            "path": p,
            "category": "log",
            "method": "HEAD",
            "check_content": False,  # 日志文件通常很大，按路径确认即可
            "content_patterns": None,
        })

    # 编辑器配置
    for p in EDITOR_CONFIG_PATHS:
        paths.append({
            "path": p,
            "category": "editor",
            "method": "HEAD",
            "check_content": True,
            "content_patterns": None,
        })

    return paths


def get_paths_by_category(category: str) -> list[dict]:
    """按分类获取探测路径

    Args:
        category: version_control / env / backup / config / debug / log / editor

    Returns:
        该分类下的所有探测路径
    """
    all_paths = get_info_paths()
    return [p for p in all_paths if p["category"] == category]


def detect_sensitive_content(text: str, content_patterns: str | None) -> dict | None:
    """检测响应内容中是否包含敏感信息

    Args:
        text: HTTP 响应正文
        content_patterns: 匹配模式组名称

    Returns:
        如果检测到敏感内容，返回 {"pattern_group": str, "matched": list, "evidence": str}，否则 None
    """
    if not content_patterns or content_patterns not in CONTENT_DETECTION_PATTERNS:
        return None

    patterns = CONTENT_DETECTION_PATTERNS[content_patterns]
    matched = []

    for pattern in patterns:
        if pattern in text:
            matched.append(pattern)

    if matched:
        return {
            "pattern_group": content_patterns,
            "matched": matched,
            "evidence": f"匹配到 {content_patterns} 特征: {', '.join(matched[:5])}",
        }

    return None


def detect_any_sensitive_content(text: str) -> list[dict]:
    """检测响应内容中是否包含任意敏感信息模式

    Args:
        text: HTTP 响应正文

    Returns:
        所有匹配到的模式组列表
    """
    results = []
    for group_name, patterns in CONTENT_DETECTION_PATTERNS.items():
        matched = [p for p in patterns if p in text]
        if matched:
            results.append({
                "pattern_group": group_name,
                "matched": matched[:5],
                "evidence": f"匹配到 {group_name} 特征: {', '.join(matched[:5])}",
            })
    return results


def _guess_content_pattern(path: str) -> str | None:
    """根据路径猜测应使用的内容检测模式

    Args:
        path: 请求路径

    Returns:
        内容模式名称 或 None
    """
    path_lower = path.lower()

    # 环境文件
    if ".env" in path_lower:
        return "env_file"

    # Git 相关
    if ".git/" in path_lower or ".git" in path_lower:
        return "git_config"

    # PHP
    if "phpinfo" in path_lower or "info.php" in path_lower:
        return "php_info"

    # Spring Actuator
    if "actuator" in path_lower:
        return "spring_actuator"

    # Apache 状态
    if "server-status" in path_lower or "server-info" in path_lower:
        return "apache_status"

    # Swagger
    if "swagger" in path_lower or "api-docs" in path_lower or "openapi" in path_lower:
        return "swagger"

    # WordPress
    if "wp-config" in path_lower or "wp-" in path_lower:
        return "wordpress_config"

    # Laravel
    if "laravel" in path_lower:
        return "laravel_log"

    # Django / Python
    if "settings.py" in path_lower or "settings/" in path_lower:
        return "settings_file"

    # ASP.NET trace
    if "trace.axd" in path_lower:
        return "dotnet_trace"

    # 备份/配置文件 — 尝试通用检测
    if any(ext in path_lower for ext in [".bak", ".old", ".orig", ".save", ".backup", "~", ".config", "config.php", "database.yml"]):
        return "env_file"

    return None
