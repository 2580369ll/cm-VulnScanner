"""XSS 跨站脚本检测插件

检测方法:
1. 反射型 XSS — 向参数注入 Payload，检测响应中是否原样回显
2. 存储型 XSS — 向表单提交 Payload，再次爬取页面检测
3. DOM-based XSS — 分析 JS 代码中的危险 Sink
"""

from bs4 import BeautifulSoup

from app.scanner.plugins.base import BasePlugin, InjectionPoint, Finding
from app.scanner.payloads.xss_payloads import get_payloads_by_level, get_dom_sinks
from app.scanner.bypass.encoder import apply_encoder


class XSSPlugin(BasePlugin):
    """XSS 检测插件"""

    name = "xss"
    vuln_type = "xss"

    async def check(self, ip: InjectionPoint) -> list[Finding]:
        findings = []

        # 1) 反射型 XSS
        reflected = await self._check_reflected(ip)
        findings.extend(reflected)

        # 2) 存储型 XSS（仅对 POST 表单）
        if ip.method == "POST" and ip.form_inputs:
            stored = await self._check_stored(ip)
            findings.extend(stored)

        # 3) DOM-based XSS
        dom = await self._check_dom(ip)
        findings.extend(dom)

        return findings

    async def _check_reflected(self, ip: InjectionPoint) -> list[Finding]:
        """反射型 XSS 检测"""
        findings = []

        # 根据 WAF 选择 Payload 等级
        waf_level = "basic"
        if self.waf_info.get("name"):
            waf_level = "medium" if self.waf_info.get("confidence") == "medium" else "advanced"

        payloads = get_payloads_by_level(waf_level)

        for payload in payloads[:10]:  # 限制探测数量
            try:
                resp = await self._send_with_payload(ip, payload)
                html = resp.text

                # 检测 Payload 在响应中的"存活"情况
                survival = self._check_payload_survival(payload, html)

                if survival["exact_match"]:
                    # Payload 完全原样出现在响应中 → 确认漏洞
                    return [Finding(
                        vuln_type="xss",
                        severity="high",
                        endpoint=ip.url,
                        parameter=ip.param_name,
                        method=ip.method,
                        payload=payload,
                        payload_variant="raw",
                        request_raw=self.format_request(
                            ip.method, ip.url,
                            dict(resp.request.headers),
                            resp.request.content.decode(errors="ignore"),
                        ),
                        response_raw=self.format_response(resp),
                        response_evidence=survival["evidence"],
                        poc=f"访问 {ip.url}?{ip.param_name}={payload} 触发弹窗",
                        description=f"反射型 XSS：参数 `{ip.param_name}` 的值被直接输出到 HTML 中，未做任何过滤",
                        remediation="对所有输出到 HTML 的用户输入进行 HTML Entity 编码，使用 CSP 头限制脚本执行",
                    )]

                elif survival["partial_match"]:
                    # Payload 被部分过滤 — 尝试绕过
                    bypass_finding = await self._try_bypass(ip, payload, html)
                    if bypass_finding:
                        return [bypass_finding]

            except Exception:
                continue

        return findings

    async def _try_bypass(self, ip: InjectionPoint, original_payload: str, original_html: str) -> Finding | None:
        """当基础 Payload 被过滤时，尝试绕过"""
        bypass_methods = self.waf_info.get("bypass_methods", ["url_encode"])

        # 从 XSS Payload 库获取中等绕过 Payload
        medium_payloads = get_payloads_by_level("medium")[len(get_payloads_by_level("basic")):]

        for payload in medium_payloads[:5]:
            try:
                resp = await self._send_with_payload(ip, payload)
                survival = self._check_payload_survival(payload, resp.text)

                if survival["exact_match"]:
                    return Finding(
                        vuln_type="xss",
                        severity="high",
                        endpoint=ip.url,
                        parameter=ip.param_name,
                        method=ip.method,
                        payload=payload,
                        payload_variant="medium_bypass",
                        request_raw=self.format_request(
                            ip.method, ip.url,
                            dict(resp.request.headers),
                            resp.request.content.decode(errors="ignore"),
                        ),
                        response_raw=self.format_response(resp),
                        response_evidence=survival["evidence"],
                        poc=f"访问 {ip.url}?{ip.param_name}={payload}",
                        description=f"反射型 XSS（绕过）：基础 Payload 被过滤，通过变体 `{payload[:80]}` 成功注入",
                        remediation="使用严格的输入白名单验证和输出编码，不依赖黑名单过滤",
                    )
            except Exception:
                continue

        return None

    async def _check_stored(self, ip: InjectionPoint) -> list[Finding]:
        """存储型 XSS 检测"""
        findings = []

        payloads = get_payloads_by_level("basic")

        test_payload = payloads[0]  # <script>alert(1)</script>

        try:
            # 提交带 Payload 的表单
            if ip.method == "POST" and ip.form_inputs:
                data = {f["name"]: "test" for f in ip.form_inputs}
                data[ip.param_name] = test_payload

                resp = await self.client.post(
                    ip.form_action or ip.url,
                    data=data,
                )

                # 如果提交成功，重新访问页面检查 Payload 是否出现
                if resp.status_code in (200, 302, 301):
                    resp2 = await self.client.get(ip.url)
                    survival = self._check_payload_survival(test_payload, resp2.text)

                    if survival["exact_match"]:
                        findings.append(Finding(
                            vuln_type="xss",
                            severity="critical",
                            endpoint=ip.url,
                            parameter=ip.param_name,
                            method="POST",
                            payload=test_payload,
                            payload_variant="stored",
                            request_raw=self.format_request(
                                "POST", ip.form_action or ip.url,
                                {"Content-Type": "application/x-www-form-urlencoded"},
                                str(data),
                            ),
                            response_raw=self.format_response(resp2),
                            response_evidence=survival["evidence"],
                            poc=f"向 {ip.url} 提交 Payload `{test_payload}`，刷新页面后触发",
                            description=f"存储型 XSS：参数 `{ip.param_name}` 的内容被存储并在页面中展示",
                            remediation="对存储的用户输入进行输出编码，使用 CSP 和 HttpOnly Cookie",
                        ))
        except Exception:
            pass

        return findings

    async def _check_dom(self, ip: InjectionPoint) -> list[Finding]:
        """DOM-based XSS 检测"""
        findings = []

        try:
            resp = await self.client.get(ip.url)
            html = resp.text
            soup = BeautifulSoup(html, "lxml")

            # 分析页面 JS 代码
            for script in soup.find_all("script"):
                if not script.string:
                    continue

                js_code = script.string
                for sink in get_dom_sinks():
                    if sink in js_code:
                        # 检查 Sink 中是否使用了 URL 参数或用户输入
                        source_patterns = [
                            "location.search",
                            "location.hash",
                            "document.URL",
                            "document.referrer",
                            "window.name",
                        ]
                        for source in source_patterns:
                            if source in js_code:
                                findings.append(Finding(
                                    vuln_type="xss",
                                    severity="medium",
                                    endpoint=ip.url,
                                    parameter=ip.param_name,
                                    method="GET",
                                    payload=f"DOM Sink: {sink} ← Source: {source}",
                                    payload_variant="dom_potential",
                                    response_raw=js_code[:2000],
                                    response_evidence=f"发现潜在 DOM XSS: {source} → {sink}",
                                    poc=f"审查 {ip.url} 的 JS 代码中 {source} 到 {sink} 的数据流",
                                    description=f"DOM-based XSS（潜在）：JS 代码将 `{source}` 传入 `{sink}`，可能存在 DOM XSS",
                                    remediation="使用 textContent 替代 innerHTML，避免将用户输入传入 eval/document.write，使用 Trusted Types",
                                ))
                                break  # 找到一个就够了

        except Exception:
            pass

        return findings

    async def _send_with_payload(self, ip: InjectionPoint, payload: str):
        """发送带 Payload 的请求"""
        if ip.method == "GET":
            return await self.client.get(ip.url, params={ip.param_name: payload})
        else:
            if ip.form_inputs:
                data = {f["name"]: "test" for f in ip.form_inputs}
                data[ip.param_name] = payload
            else:
                data = {ip.param_name: payload}
            return await self.client.post(
                ip.form_action or ip.url,
                data=data,
            )

    def _check_payload_survival(self, payload: str, html: str) -> dict:
        """检查 Payload 在响应中的存活情况

        Returns:
            {"exact_match": bool, "partial_match": bool, "evidence": str}
        """
        # 1) 完全匹配
        if payload in html:
            # 截取 Payload 周围的上下文作为证据
            idx = html.index(payload)
            start = max(0, idx - 50)
            end = min(len(html), idx + len(payload) + 50)
            return {
                "exact_match": True,
                "partial_match": True,
                "evidence": html[start:end],
            }

        # 2) 检查是否被部分过滤
        # 提取 Payload 中的关键字符串
        key_parts = ["<script>", "alert(", "onerror=", "onload=", "onfocus="]
        for part in key_parts:
            if part in payload and part in html:
                return {
                    "exact_match": False,
                    "partial_match": True,
                    "evidence": f"关键部分 `{part}` 在响应中存在",
                }

        # 3) 检查 HTML 编码后的形式
        import html as html_module
        encoded = html_module.escape(payload)
        if encoded in html:
            return {
                "exact_match": False,
                "partial_match": True,
                "evidence": f"Payload 被 HTML 编码: {encoded[:100]}",
            }

        return {"exact_match": False, "partial_match": False, "evidence": ""}
