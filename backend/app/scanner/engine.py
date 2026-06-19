"""扫描调度引擎 — 统筹爬虫、WAF检测、插件执行、结果汇总"""

import asyncio
import json
from urllib.parse import urlparse

import httpx

from app.config import settings
from app.scanner.crawler import Crawler
from app.scanner.waf_detector import WAFDetector
from app.scanner.plugins.base import InjectionPoint, Finding
from app.scanner.plugins.sqli import SQLiPlugin
from app.scanner.plugins.xss import XSSPlugin
from app.scanner.plugins.file_upload import FileUploadPlugin


class ScanEngine:
    """漏洞扫描引擎"""

    def __init__(
        self,
        target_url: str,
        scan_depth: int = 2,
        vuln_types: list[str] | None = None,
        custom_headers: dict | None = None,
        custom_cookies: dict | None = None,
        proxy: str | None = None,
        progress_callback=None,
    ):
        self.target_url = target_url.rstrip("/")
        self.scan_depth = min(scan_depth, settings.max_scan_depth)
        self.vuln_types = vuln_types or ["sqli", "xss", "file_upload"]
        self.custom_headers = custom_headers or {}
        self.custom_cookies = custom_cookies or {}
        self.proxy = proxy
        self.progress = progress_callback

        # 解析目标域名
        parsed = urlparse(self.target_url)
        self.base_domain = parsed.netloc
        self.base_scheme = parsed.scheme

        # HTTP 客户端
        limits = httpx.Limits(max_connections=20, max_keepalive_connections=10)
        self.client_kwargs = {
            "timeout": httpx.Timeout(settings.request_timeout),
            "limits": limits,
            "follow_redirects": True,
            "verify": False,
        }
        if proxy:
            self.client_kwargs["proxy"] = proxy

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

        return [f.to_dict() for f in all_findings]

    def _create_plugins(self, client: httpx.AsyncClient, waf_info: dict) -> list:
        """根据配置创建插件列表"""
        plugins = []

        plugin_map = {
            "sqli": (SQLiPlugin, "SQL注入"),
            "xss": (XSSPlugin, "跨站脚本"),
            "file_upload": (FileUploadPlugin, "文件上传"),
        }

        for vuln_type in self.vuln_types:
            if vuln_type in plugin_map:
                plugin_cls, _ = plugin_map[vuln_type]
                plugins.append(plugin_cls(client, waf_info))

        return plugins
