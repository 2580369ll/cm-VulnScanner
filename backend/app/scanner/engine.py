"""扫描调度引擎 — 统筹爬虫、WAF检测、插件执行、结果汇总"""

import asyncio
import json
from urllib.parse import urlparse

import httpx

MAX_RETRIES = 3
RETRY_DELAY_BASE = 2  # 秒，指数退避: 2s → 4s → 8s

from app.config import settings
from app.scanner.crawler import Crawler
from app.scanner.waf_detector import WAFDetector
from app.scanner.plugins.base import InjectionPoint, Finding
from app.scanner.plugins.sqli import SQLiPlugin
from app.scanner.plugins.xss import XSSPlugin
from app.scanner.plugins.file_upload import FileUploadPlugin
from app.scanner.plugins.command_injection import CommandInjectionPlugin
from app.scanner.plugins.path_traversal import PathTraversalPlugin
from app.scanner.plugins.ssrf import SSRFPlugin
from app.scanner.plugins.info_disclosure import InfoDisclosurePlugin
from app.scanner.plugins.ssti import SSTIPlugin
from app.scanner.plugins.idor import IDORPlugin
from app.scanner.plugins.open_redirect import OpenRedirectPlugin
from app.scanner.plugins.csrf import CSRFPlugin
from app.scanner.plugins.nuclei_plugin import NucleiPlugin


class ScanEngine:
    """漏洞扫描引擎"""

    def __init__(
        self,
        target_url: str,
        scan_depth: int = 2,
        vuln_types: list[str] | None = None,
        custom_headers: dict | None = None,
        custom_cookies: dict | None = None,
        custom_payloads: dict | None = None,
        proxy: str | None = None,
        progress_callback=None,
        task_id: str = "",
    ):
        self.target_url = target_url.rstrip("/")
        self.scan_depth = min(scan_depth, settings.max_scan_depth)
        self.vuln_types = vuln_types or ["sqli", "xss", "file_upload"]
        self.custom_headers = custom_headers or {}
        self.custom_cookies = custom_cookies or {}
        self.custom_payloads = custom_payloads or {}
        self.proxy = proxy
        self.progress = progress_callback
        self.task_id = task_id

        # 解析目标域名
        parsed = urlparse(self.target_url)
        self.base_domain = parsed.netloc
        self.base_scheme = parsed.scheme

        # HTTP 客户端 — 附加全局 Cookie 和 Headers
        default_headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
        }
        if custom_headers:
            default_headers.update(custom_headers)

        limits = httpx.Limits(max_connections=100, max_keepalive_connections=20)
        self.client_kwargs = {
            "timeout": httpx.Timeout(settings.request_timeout),
            "limits": limits,
            "follow_redirects": True,
            "verify": False,
            "headers": default_headers,
        }
        if custom_cookies:
            # httpx 用 cookies 参数传递
            self.client_kwargs["cookies"] = custom_cookies
        if proxy:
            self.client_kwargs["proxy"] = proxy

        # 并发控制：单目标最多 10 并发
        self.semaphore = asyncio.Semaphore(10)

    async def run(self) -> list[dict]:
        """执行完整扫描流程"""
        all_findings: list[Finding] = []

        if self.progress:
            await self.progress({"type": "scan_start", "target": self.target_url})

        async with httpx.AsyncClient(**self.client_kwargs) as client:
            # Phase 1: WAF 检测
            if self.progress:
                await self.progress({"type": "phase", "phase": "waf_detection"})

            waf_info = {}
            if settings.waf_detection_enabled:
                detector = WAFDetector(client)
                waf_info = await detector.detect(self.target_url)
                if self.progress and waf_info:
                    await self.progress({
                        "type": "waf_detected",
                        "waf": waf_info.get("name", "unknown"),
                    })

            # Phase 2: 爬虫 — 发现注入点
            if self.progress:
                await self.progress({"type": "phase", "phase": "crawling"})

            crawler = Crawler(
                client=client,
                base_domain=self.base_domain,
                max_depth=self.scan_depth,
                max_pages=settings.max_pages_per_target,
            )
            injection_points = await crawler.crawl(self.target_url)

            if self.progress:
                await self.progress({
                    "type": "crawl_complete",
                    "total_endpoints": len(injection_points),
                })

            # Phase 3: 依次对每个注入点运行插件
            plugins = self._create_plugins(client, waf_info)

            for idx, ip in enumerate(injection_points):
                # 检查取消信号
                if self._is_cancelled():
                    if self.progress:
                        await self.progress({"type": "scan_cancelled"})
                    return []

                if self.progress:
                    await self.progress({
                        "type": "scanning",
                        "current": idx + 1,
                        "total": len(injection_points),
                        "endpoint": ip.url,
                    })

                for plugin in plugins:
                    try:
                        findings = await plugin.check(ip)
                        for f in findings:
                            all_findings.append(f)
                            if self.progress:
                                await self.progress({
                                    "type": "vulnerability_found",
                                    "vuln_type": f.vuln_type,
                                    "severity": f.severity,
                                    "endpoint": f.endpoint,
                                    "payload": f.payload[:200],
                                })
                    except Exception as e:
                        if self.progress:
                            await self.progress({
                                "type": "plugin_error",
                                "plugin": plugin.name,
                                "error": str(e),
                            })

                if self.progress:
                    await self.progress({
                        "type": "endpoint_scanned",
                        "current": idx + 1,
                        "total": len(injection_points),
                    })

                # 请求间隔
                await asyncio.sleep(settings.scan_delay)

        if self.progress:
            await self.progress({
                "type": "scan_complete",
                "total_vulns": len(all_findings),
            })

        # 去重：同一端点+参数+类型只保留最高置信度
        all_findings = self._deduplicate_findings(all_findings)

        return [f.to_dict() for f in all_findings]

    def _create_plugins(self, client: httpx.AsyncClient, waf_info: dict) -> list:
        """根据配置创建插件列表"""
        plugin_map = {
            "sqli": SQLiPlugin,
            "xss": XSSPlugin,
            "file_upload": FileUploadPlugin,
            "command_injection": CommandInjectionPlugin,
            "path_traversal": PathTraversalPlugin,
            "ssrf": SSRFPlugin,
            "info_disclosure": InfoDisclosurePlugin,
            "ssti": SSTIPlugin,
            "idor": IDORPlugin,
            "open_redirect": OpenRedirectPlugin,
            "csrf": CSRFPlugin,
            "nuclei": NucleiPlugin,
        }

        plugins = []
        for vuln_type in self.vuln_types:
            if vuln_type in plugin_map:
                plugin = plugin_map[vuln_type](client, waf_info)
                # 注入自定义 Payload
                if vuln_type in self.custom_payloads:
                    plugin.custom_payloads = self.custom_payloads[vuln_type]
                plugins.append(plugin)

        return plugins

    async def _fetch_with_retry(self, client, url, method="GET", **kwargs):
        import httpx as _httpx
        for attempt in range(MAX_RETRIES):
            try:
                resp = await client.request(method, url, **kwargs)
                return resp
            except _httpx.TimeoutException:
                if attempt < MAX_RETRIES - 1:
                    await asyncio.sleep(RETRY_DELAY_BASE * (2 ** attempt))
            except _httpx.ConnectError:
                break
            except Exception:
                if attempt < MAX_RETRIES - 1:
                    await asyncio.sleep(RETRY_DELAY_BASE)
        return None

    def _is_cancelled(self) -> bool:
        """检查 Redis 中是否有取消信号"""
        if not self.task_id:
            return False
        try:
            import redis
            r = redis.from_url(settings.redis_url)
            cancelled = r.exists(f"cancel:{self.task_id}")
            r.close()
            return bool(cancelled)
        except Exception:
            return False

    def _deduplicate_findings(self, findings: list[Finding]) -> list[Finding]:
        """去重：同一 (endpoint, parameter, vuln_type) 只保留最高置信度的"""
        best: dict[tuple, Finding] = {}
        for f in findings:
            key = (f.endpoint, f.parameter, f.vuln_type)
            if key not in best or f.confidence > best[key].confidence:
                best[key] = f
        return list(best.values())
