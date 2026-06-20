"""Nuclei 模板检测插件

加载内置 Nuclei 模板，对每个发现的端点执行匹配检测。
"""

import os
from pathlib import Path

from app.scanner.plugins.base import BasePlugin, InjectionPoint, Finding
from app.scanner.nuclei.loader import load_templates_from_dir
from app.scanner.nuclei.executor import template_to_finding


class NucleiPlugin(BasePlugin):
    """Nuclei 模板检测插件 — 集成社区模板检测能力"""

    name = "nuclei"
    vuln_type = "nuclei"

    def __init__(self, http_client, waf_info: dict | None = None):
        super().__init__(http_client, waf_info)
        self.templates = self._load_builtin_templates()

    def _load_builtin_templates(self):
        """加载内置模板目录"""
        # 内置模板路径
        builtin = Path(__file__).parent.parent / "nuclei" / "templates"
        if builtin.exists():
            return load_templates_from_dir(str(builtin))
        return []

    async def check(self, ip: InjectionPoint) -> list[Finding]:
        findings = []

        # 只对 HTTP 200 的端点做 Nuclei 匹配（避免浪费请求）
        if not self.templates:
            return findings

        for template in self.templates:
            # 每个模板尝试匹配端点 URL
            finding = await template_to_finding(
                self.client, template, ip.url, ip.param_name
            )
            if finding:
                findings.append(finding)
                if len(findings) >= 10:  # 单端点最多10个
                    break

        return findings
