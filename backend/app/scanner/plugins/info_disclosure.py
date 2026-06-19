"""信息泄露检测插件

检测方法:
1. 对每个常见敏感路径发起 HEAD 请求（快速探测文件存在性）
2. HEAD 返回 200 → 改用 GET 请求获取内容并验证
3. HEAD 返回 403 → 文件存在但受保护（记录下来）
4. GET 200 + 内容匹配 → 确认信息泄露
5. GET 200 + 文件名可疑但内容未确认 → 潜在泄露

置信度规则:
- 0.95: GET 200 + 响应内容匹配确认模式
- 0.75: GET 200 + 文件名高度可疑但内容未确认
- 0.50: HEAD 403 或 GET 401/403 (文件存在但受保护 — 信息级别)
- 0.40: GET 200 + 无法确认内容（可能是默认页面）
"""

from urllib.parse import urljoin

import httpx

from app.scanner.plugins.base import BasePlugin, InjectionPoint, Finding
from app.scanner.payloads.info_disclosure_payloads import (
    get_info_paths,
    get_paths_by_category,
    detect_sensitive_content,
    detect_any_sensitive_content,
)


class InfoDisclosurePlugin(BasePlugin):
    """信息泄露检测插件"""

    name = "info_disclosure"
    vuln_type = "info_disclosure"

    # 高危文件扩展名和文件名模式（即使内容未确认也值得关注）
    HIGH_RISK_FILENAMES = [
        ".env",
        ".git/config",
        "web.config",
        "database.yml",
        "wp-config.php",
        "database.sql",
        "credentials",
        "secrets",
        "dump.sql",
        "backup.sql",
    ]

    # 每个分类的探测路径上限
    MAX_PATHS_PER_CATEGORY = {
        "version_control": 15,
        "env": 20,
        "backup": 30,
        "config": 30,
        "debug": 25,
        "log": 20,
        "editor": 10,
    }

    async def check(self, ip: InjectionPoint) -> list[Finding]:
        """对目标基础 URL 探测常见敏感路径

        Args:
            ip: 注入点信息（使用 ip.url 作为基础 URL）

        Returns:
            发现的漏洞列表
        """
        findings = []

        # 获取基础 URL
        base_url = self._get_base_url(ip.url)
        if not base_url:
            return findings

        # 获取所有探测路径，按分类分批处理
        all_paths = get_info_paths()

        # 按分类整理，限制每个分类的最大探测数
        categorized = {}
        for p in all_paths:
            cat = p["category"]
            if cat not in categorized:
                categorized[cat] = []
            categorized[cat].append(p)

        for cat, paths in categorized.items():
            limit = self.MAX_PATHS_PER_CATEGORY.get(cat, 15)
            prioritized_paths = self._prioritize_paths(paths, cat)[:limit]

            for path_info in prioritized_paths:
                finding = await self._check_path(base_url, path_info, ip)
                if finding:
                    findings.append(finding)

                    # 发现高危文件后跳过同分类的其他路径
                    if finding.confidence >= 0.90:
                        break

            if len(findings) >= 5:
                break  # 已发现足够多的信息泄露，停止进一步探测

        return findings[:10]  # 最多返回 10 个发现

    async def _check_path(
        self, base_url: str, path_info: dict, ip: InjectionPoint
    ) -> Finding | None:
        """探测单个路径

        Args:
            base_url: 目标基础 URL
            path_info: 路径信息 {"path", "category", "method", "check_content", "content_patterns"}
            ip: 原始注入点

        Returns:
            Finding 或 None
        """
        path = path_info["path"]
        full_url = self._build_url(base_url, path)

        # 1) HEAD 请求快速探测
        status_code, content_length = await self._head_request(full_url)

        if status_code is None:
            return None  # 连接失败，跳过

        # HEAD 200 → 文件可访问
        if status_code == 200:
            # 对于小文件 / 需要内容确认的文件，发送 GET 请求
            if path_info.get("check_content", True):
                resp, body = await self._get_request(full_url)

                if resp is not None:
                    return self._analyze_get_response(
                        path_info, full_url, resp.status_code, body, ip
                    )

            # 不需要内容确认（如日志文件路径命中即确认）
            else:
                confidence = 0.60
                severity = "medium"

                # 高价值日志文件提升严重度
                if _is_high_value_log(path):
                    confidence = 0.75
                    severity = "high"

                return Finding(
                    vuln_type="info_disclosure",
                    severity=severity,
                    confidence=confidence,
                    endpoint=full_url,
                    parameter="",
                    method="GET",
                    payload=path,
                    payload_variant="path_discovery",
                    request_raw=self.format_request("HEAD", full_url, {}, ""),
                    response_raw=f"HEAD {full_url} → {status_code}" if status_code == 200 else "",
                    response_evidence=(
                        f"HEAD 请求返回 {status_code}，文件 `{path}` 可公开访问 "
                        f"(Content-Length: {content_length})\n分类: {path_info['category']}"
                    ),
                    poc=f"curl '{full_url}'",
                    description=(
                        f"信息泄露：`{path}` 文件可公开访问（{path_info['category']} 类）"
                    ),
                    remediation=(
                        f"1. 将 {path} 从 Web 可访问目录移除\n"
                        "2. 使用 .htaccess / web.config 限制直接访问\n"
                        "3. 确保部署流程中不将敏感文件上传到生产环境"
                    ),
                )

        # HEAD 403 → 文件存在但受保护
        elif status_code == 403:
            # 高价值路径值得记录
            if self._is_high_value_path(path):
                return Finding(
                    vuln_type="info_disclosure",
                    severity="info",
                    confidence=0.50,
                    endpoint=full_url,
                    parameter="",
                    method="HEAD",
                    payload=path,
                    payload_variant="protected_exists",
                    request_raw=self.format_request("HEAD", full_url, {}, ""),
                    response_raw=f"HEAD {full_url} → 403 Forbidden",
                    response_evidence=(
                        f"HEAD 请求返回 403，文件 `{path}` 存在于服务器但受访问控制保护\n"
                        f"分类: {path_info['category']}"
                    ),
                    poc=f"# 尝试访问: curl '{full_url}'\n# 可能需要绕过访问控制",
                    description=(
                        f"信息泄露（受限）：`{path}` 文件存在于服务器但返回 403 Forbidden，"
                        f"攻击者可能通过路径穿越或其他方式访问"
                    ),
                    remediation=(
                        f"1. 确认 {path} 是否应该对外暴露\n"
                        "2. 如不需要，从 Web 目录删除或移动到非公开目录\n"
                        "3. 配置严格的 URL 访问规则"
                    ),
                )

        # HEAD 401 → 需要认证
        elif status_code == 401:
            if self._is_high_value_path(path):
                return Finding(
                    vuln_type="info_disclosure",
                    severity="info",
                    confidence=0.45,
                    endpoint=full_url,
                    parameter="",
                    method="HEAD",
                    payload=path,
                    payload_variant="auth_required",
                    request_raw=self.format_request("HEAD", full_url, {}, ""),
                    response_raw=f"HEAD {full_url} → 401 Unauthorized",
                    response_evidence=(
                        f"HEAD 请求返回 401，`{path}` 可能需要身份验证\n"
                        f"分类: {path_info['category']}"
                    ),
                    poc=f"curl -u user:pass '{full_url}'",
                    description=(
                        f"信息泄露（需认证）：`{path}` 路径存在但需要认证"
                    ),
                    remediation=f"确认 `{path}` 不应暴露在外部网络中",
                )

        return None  # 404 或其他状态 — 文件不存在

    async def _head_request(self, url: str) -> tuple[int | None, int]:
        """发送 HEAD 请求

        Returns:
            (status_code, content_length) — status_code 为 None 表示连接失败
        """
        try:
            resp = await self.client.head(
                url,
                follow_redirects=True,
            )
            content_length = int(resp.headers.get("Content-Length", 0))
            return resp.status_code, content_length
        except httpx.TimeoutException:
            return None, 0
        except Exception:
            return None, 0

    async def _get_request(self, url: str) -> tuple[httpx.Response | None, str]:
        """发送 GET 请求获取内容

        Returns:
            (response, body_text) — response 为 None 表示失败
        """
        try:
            resp = await self.client.get(
                url,
                follow_redirects=False,
            )
            return resp, resp.text
        except Exception:
            return None, ""

    def _analyze_get_response(
        self,
        path_info: dict,
        full_url: str,
        status_code: int,
        body: str,
        ip: InjectionPoint,
    ) -> Finding | None:
        """分析 GET 响应内容，生成 Finding

        Args:
            path_info: 路径信息
            full_url: 完整请求 URL
            status_code: GET 响应状态码
            body: 响应正文
            ip: 原始注入点

        Returns:
            Finding 或 None
        """
        if status_code != 200:
            return None

        path = path_info["path"]
        content_patterns = path_info.get("content_patterns")

        # 1) 使用指定模式检测
        confirmed = None
        if content_patterns:
            confirmed = detect_sensitive_content(body, content_patterns)

        # 2) 如果指定模式未匹配，尝试通用检测
        if not confirmed:
            any_matches = detect_any_sensitive_content(body)
            if any_matches:
                confirmed = any_matches[0]  # 使用第一个匹配

        # 3) 确认泄露 — 高置信度
        if confirmed:
            return Finding(
                vuln_type="info_disclosure",
                severity=self._determine_severity(path, confirmed),
                confidence=0.95,
                endpoint=full_url,
                parameter="",
                method="GET",
                payload=path,
                payload_variant="confirmed",
                request_raw=self.format_request(
                    "GET", full_url,
                    {},
                    f"GET {path}",
                ),
                response_raw=self._truncate_body(body, 5000),
                response_evidence=confirmed.get("evidence", ""),
                poc=f"curl '{full_url}'",
                description=(
                    f"信息泄露（已确认）：`{path}` 文件包含敏感信息 — "
                    f"{confirmed.get('pattern_group', '未知')} "
                    f"({', '.join(confirmed.get('matched', [])[:3])})"
                ),
                remediation=self._build_remediation(path, path_info["category"]),
            )

        # 4) 内容未确认但文件名高度可疑
        if self._is_high_value_path(path):
            return Finding(
                vuln_type="info_disclosure",
                severity="medium",
                confidence=0.75,
                endpoint=full_url,
                parameter="",
                method="GET",
                payload=path,
                payload_variant="suspicious_file",
                request_raw=self.format_request(
                    "GET", full_url,
                    {},
                    f"GET {path}",
                ),
                response_raw=self._truncate_body(body, 2000),
                response_evidence=(
                    f"文件 `{path}` 可公开访问（{path_info['category']} 类），"
                    f"响应长度 {len(body)} 字节，内容未确认含敏感数据"
                ),
                poc=f"curl '{full_url}'",
                description=(
                    f"信息泄露（可疑）：`{path}` 文件可公开访问，"
                    f"文件名暗示可能包含敏感信息"
                ),
                remediation=self._build_remediation(path, path_info["category"]),
            )

        # 5) 响应存在但无法确认（可能是默认页面的 200）
        # 如果 body 较短且没有 HTML 特征，可能是有效内容
        body_len = len(body)
        is_likely_real_content = (
            body_len > 10
            and body_len < 100000  # 小于 100KB，不是大型默认页面
            and "<html" not in body[:200].lower()
            and "<!doctype" not in body[:200].lower()
        )

        if is_likely_real_content and body_len > 50:
            return Finding(
                vuln_type="info_disclosure",
                severity="low",
                confidence=0.40,
                endpoint=full_url,
                parameter="",
                method="GET",
                payload=path,
                payload_variant="unconfirmed",
                request_raw=self.format_request("GET", full_url, {}, f"GET {path}"),
                response_raw=self._truncate_body(body, 1000),
                response_evidence=(
                    f"路径 `{path}` 返回 200 且有非 HTML 响应 ({body_len} 字节)，"
                    f"建议人工审查"
                ),
                poc=f"curl '{full_url}' | head -20",
                description=(
                    f"信息泄露（待确认）：`{path}` 返回非 HTML 内容 ({body_len} 字节)，"
                    f"可能需要人工确认"
                ),
                remediation=f"审查 `{path}` 的内容，确认是否包含敏感信息",
            )

        return None

    def _get_base_url(self, url: str) -> str:
        """从 URL 中提取基础 URL"""
        if not url:
            return ""

        # 确保以 / 结尾以便后续拼接
        return url.rstrip("/") if url.endswith("/") else url

    def _build_url(self, base_url: str, path: str) -> str:
        """拼接基础 URL 和路径

        Args:
            base_url: 基础 URL (如 http://example.com)
            path: 相对路径 (如 /.env 或 /actuator/health)

        Returns:
            完整 URL
        """
        # 如果 path 已经是相对路径（以 / 开头）
        if path.startswith("/"):
            return f"{base_url}{path}"

        # 如果 path 是绝对 URL
        if path.startswith("http://") or path.startswith("https://"):
            return path

        # 其他情况 — 用 urljoin
        return urljoin(f"{base_url}/", path)

    def _is_high_value_path(self, path: str) -> bool:
        """判断路径是否为高价值目标"""
        path_lower = path.lower()
        for keyword in self.HIGH_RISK_FILENAMES:
            if keyword in path_lower:
                return True
        return False

    def _prioritize_paths(self, paths: list[dict], category: str) -> list[dict]:
        """对探测路径按价值排序

        高优先级：
        - .env 文件
        - Git 配置
        - 数据库备份
        - WordPress 配置
        - 调试端点
        """
        def priority_score(p: dict) -> int:
            path = p["path"].lower()
            score = 0

            if ".env" in path:
                score += 100
            if ".git/" in path:
                score += 90
            if "database" in path or ".sql" in path or "dump" in path:
                score += 80
            if "wp-config" in path:
                score += 75
            if "web.config" in path:
                score += 70
            if "actuator" in path:
                score += 85
            if "phpinfo" in path:
                score += 65
            if "backup" in path or ".bak" in path or ".old" in path:
                score += 50
            if "server-status" in path or "server-info" in path:
                score += 55
            if "trace.axd" in path:
                score += 60
            if "swagger" in path or "api-docs" in path:
                score += 40
            if ".log" in path:
                score += 35

            return -score  # 负数使高优先级排在前面

        return sorted(paths, key=priority_score)

    def _determine_severity(self, path: str, confirmed: dict | None) -> str:
        """根据路径和确认内容判定严重等级

        Returns:
            critical / high / medium / low / info
        """
        path_lower = path.lower()
        pattern_group = confirmed.get("pattern_group", "") if confirmed else ""

        # Critical: 环境变量（含密钥）、Git 完整配置
        if pattern_group == "env_file" and ".env" in path_lower:
            return "critical"
        if ".git/config" in path_lower and pattern_group == "git_config":
            return "critical"
        if "database.sql" in path_lower or "dump.sql" in path_lower:
            return "critical"

        # High: 其他配置泄露、数据库配置
        if pattern_group in ("env_file", "wordpress_config", "settings_file"):
            return "high"
        if "web.config" in path_lower:
            return "high"
        if "actuator" in path_lower:
            return "high"

        # Medium: 调试信息、日志
        if pattern_group in ("spring_actuator", "php_info", "apache_status", "swagger"):
            return "medium"
        if any(kw in path_lower for kw in [".log", "debug", "trace.axd"]):
            return "medium"

        # Low: 其他可访问文件
        return "low"

    def _build_remediation(self, path: str, category: str) -> str:
        """根据路径和分类生成修复建议"""
        category_remediation = {
            "version_control": (
                "1. 将 .git/.svn/.hg 目录移出 Web 根目录\n"
                "2. 在 Web 服务器配置中禁止访问隐藏目录\n"
                "3. 使用部署脚本确保版本控制文件不被同步到生产环境"
            ),
            "env": (
                "1. 将 .env 文件移出 Web 可访问目录\n"
                "2. 使用环境变量而不是 .env 文件配置生产环境\n"
                "3. 在 .gitignore 中添加 .env\n"
                "4. 配置 Web 服务器禁止访问以点开头的文件"
            ),
            "backup": (
                "1. 删除所有暴露的备份文件\n"
                "2. 将备份文件存储在 Web 目录之外\n"
                "3. 配置 Web 服务器禁止访问 *.bak, *~, *.old, *.orig 文件"
            ),
            "config": (
                "1. 将配置文件移出 Web 可访问目录\n"
                "2. 使用最小权限原则限制配置文件读取\n"
                "3. 敏感凭据使用密钥管理服务 (KMS)"
            ),
            "debug": (
                "1. 在生产环境中关闭调试模式\n"
                "2. 移除 phpinfo.php / info.php / test.php\n"
                "3. 使用 IP 白名单限制调试端点访问\n"
                "4. 为 Actuator 端点配置 Spring Security"
            ),
            "log": (
                "1. 将日志文件存储在 Web 目录之外\n"
                "2. 配置 Web 服务器禁止访问 .log 文件\n"
                "3. 定期清理和轮转日志文件"
            ),
            "editor": (
                "1. 在 .gitignore 中添加 .vscode/、.idea/、.DS_Store\n"
                "2. 配置 Web 服务器禁止访问隐藏目录\n"
                "3. 使用全局 .gitignore 模板"
            ),
        }

        base = category_remediation.get(category, "1. 从 Web 可访问目录中删除或限制该文件\n2. 审查部署流程")
        return (
            f"{base}\n"
            "--- 通用建议 ---\n"
            "- 实施定期安全扫描检测敏感文件泄露\n"
            "- 制定部署前安全检查清单\n"
            "- 配置 WAF 规则阻止敏感路径访问"
        )

    def _truncate_body(self, body: str, max_length: int = 5000) -> str:
        """截断响应正文，避免 Finding 过大"""
        if len(body) <= max_length:
            return body
        return body[:max_length] + f"\n\n... [已截断，原长度 {len(body)} 字符]"


def _is_high_value_log(path: str) -> bool:
    """判断日志文件是否为高价值目标"""
    high_value_logs = [
        "laravel.log",
        "production.log",
        "error.log",
        "debug.log",
        "mysql.log",
    ]
    path_lower = path.lower()
    return any(log_name in path_lower for log_name in high_value_logs)
