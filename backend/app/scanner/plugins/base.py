"""漏洞检测插件基类"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class InjectionPoint:
    """注入点信息"""
    url: str
    method: str = "GET"  # GET / POST
    param_name: str = ""
    param_type: str = "query"  # query / body / header / cookie / file
    form_action: str = ""      # 表单 action (用于 POST)
    form_inputs: list = field(default_factory=list)  # 表单字段列表
    headers: dict = field(default_factory=dict)
    cookies: dict = field(default_factory=dict)


@dataclass
class Finding:
    """漏洞发现结果"""
    vuln_type: str          # sqli / xss / file_upload
    severity: str           # critical / high / medium / low / info
    endpoint: str           # 漏洞所在 URL
    parameter: str          # 漏洞参数
    method: str             # HTTP 方法
    payload: str            # 触发漏洞的 Payload
    payload_variant: str = ""     # 使用的绕过变体名称
    request_raw: str = ""        # 原始 HTTP 请求（文本格式）
    response_raw: str = ""       # 原始 HTTP 响应（文本格式）
    response_evidence: str = ""  # 响应中的漏洞证据片段
    poc: str = ""                # 可复现 PoC
    description: str = ""        # 漏洞描述
    remediation: str = ""        # 修复建议

    def to_dict(self) -> dict:
        return {
            "type": self.vuln_type,
            "severity": self.severity,
            "endpoint": self.endpoint,
            "parameter": self.parameter,
            "method": self.method,
            "payload": self.payload,
            "payload_variant": self.payload_variant,
            "request_raw": self.request_raw,
            "response_raw": self.response_raw,
            "response_evidence": self.response_evidence,
            "poc": self.poc,
            "description": self.description,
            "remediation": self.remediation,
        }


class BasePlugin(ABC):
    """漏洞检测插件基类"""

    name: str = "base"
    vuln_type: str = "unknown"
    severity: str = "info"

    def __init__(self, http_client, waf_info: dict | None = None):
        """
        Args:
            http_client: httpx.AsyncClient 实例
            waf_info: WAF 检测结果 {"name": "xxx", "bypass_methods": [...]}
        """
        self.client = http_client
        self.waf_info = waf_info or {}

    @abstractmethod
    async def check(self, injection_point: InjectionPoint) -> list[Finding]:
        """检测注入点是否存在漏洞

        Args:
            injection_point: 注入点信息

        Returns:
            发现的漏洞列表（空列表表示安全）
        """
        pass

    def format_request(self, method: str, url: str, headers: dict, body: str = "") -> str:
        """格式化 HTTP 请求为文本"""
        lines = [f"{method} {url} HTTP/1.1"]
        for k, v in headers.items():
            lines.append(f"{k}: {v}")
        if body:
            lines.append("")
            lines.append(body)
        return "\n".join(lines)

    def format_response(self, response) -> str:
        """格式化 HTTP 响应为文本"""
        lines = [f"HTTP/1.1 {response.status_code} {response.reason_phrase or ''}"]
        for k, v in response.headers.items():
            lines.append(f"{k}: {v}")
        lines.append("")
        lines.append(response.text[:5000])
        return "\n".join(lines)
