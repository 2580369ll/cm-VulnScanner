"""Open Redirect 检测插件"""

from app.scanner.plugins.base import BasePlugin, InjectionPoint, Finding
from app.scanner.payloads.open_redirect_payloads import get_redirect_params, get_redirect_payloads


class OpenRedirectPlugin(BasePlugin):
    """URL 重定向检测插件"""

    name = "open_redirect"
    vuln_type = "open_redirect"

    async def check(self, ip: InjectionPoint) -> list[Finding]:
        findings = []

        # 只在参数名匹配时检查
        if not self._is_redirect_param(ip.param_name):
            return findings

        payloads = get_redirect_payloads()
        for payload in payloads[:5]:
            try:
                resp = await self._send(ip, payload)
                # 检查 Location 头是否包含我们的 Payload
                location = resp.headers.get("location", "")
                if "evil.com" in location.lower():
                    return [Finding(
                        vuln_type="open_redirect",
                        severity="medium",
                        confidence=0.90,
                        endpoint=ip.url,
                        parameter=ip.param_name,
                        method=ip.method,
                        payload=payload,
                        payload_variant="direct",
                        request_raw=f"{ip.method} {ip.url}?{ip.param_name}={payload}",
                        response_raw=f"Location: {location}",
                        response_evidence=f"重定向到外部域名: {location}",
                        poc=f"curl -v '{ip.url}?{ip.param_name}={payload}'",
                        description=f"Open Redirect: 参数 `{ip.param_name}` 可重定向到任意外部 URL",
                        remediation="使用白名单限制重定向目标，禁止用户控制完整URL",
                    )]

                # 检查状态码 301/302 + evil.com
                if resp.status_code in (301, 302) and "evil.com" in location.lower():
                    return [Finding(
                        vuln_type="open_redirect",
                        severity="medium",
                        confidence=0.85,
                        endpoint=ip.url,
                        parameter=ip.param_name,
                        method=ip.method,
                        payload=payload,
                        payload_variant="direct",
                        poc=f"curl -v '{ip.url}?{ip.param_name}={payload}'",
                        description=f"Open Redirect (HTTP {resp.status_code})",
                        remediation="使用白名单限制重定向目标",
                    )]
            except Exception:
                continue

        return findings

    async def _send(self, ip: InjectionPoint, payload: str):
        if ip.method == "GET":
            return await self.client.get(ip.url, params={ip.param_name: payload}, follow_redirects=False)
        else:
            return await self.client.post(ip.url, data={ip.param_name: payload}, follow_redirects=False)

    def _is_redirect_param(self, name: str) -> bool:
        return name.lower() in [p.lower() for p in get_redirect_params()]
