"""路径穿越 / 本地文件包含 (LFI) 检测插件

检测方法:
1. 发送路径穿越 Payload 到参数
2. 检查响应中是否出现目标文件的内容特征
3. 支持 GET 和 POST 两种注入点
4. 检测 PHP 封装器（php://filter, data://, expect://）

置信度:
- 0.90: 响应中出现明确的文件内容特征（如 /etc/passwd 的 root:x:0:0:）
- 0.60: 响应中出现了错误消息或异常长/短内容，但无法明确确认文件内容
"""

import re

import httpx

from app.scanner.plugins.base import BasePlugin, InjectionPoint, Finding
from app.scanner.payloads.path_traversal_payloads import (
    get_linux_traversal,
    get_windows_traversal,
    get_encoded_traversal,
    get_php_specific,
    get_detection_patterns,
    match_file_content,
)
from app.scanner.bypass import apply_bypass


class PathTraversalPlugin(BasePlugin):
    """路径穿越 / LFI 检测插件"""

    name = "path_traversal"
    vuln_type = "path_traversal"
    severity = "high"

    CONTENT_MATCH_CONFIDENCE = 0.90
    ERROR_BASED_CONFIDENCE = 0.60

    MAX_LINUX_PAYLOADS = 5
    MAX_WINDOWS_PAYLOADS = 4
    MAX_ENCODED_PAYLOADS = 4
    MAX_PHP_PAYLOADS = 3

    async def check(self, ip: InjectionPoint) -> list[Finding]:
        findings = []

        linux_finding = await self._check_linux_traversal(ip)
        if linux_finding:
            findings.append(linux_finding)
            return findings

        windows_finding = await self._check_windows_traversal(ip)
        if windows_finding:
            findings.append(windows_finding)
            return findings

        encoded_finding = await self._check_encoded_traversal(ip)
        if encoded_finding:
            findings.append(encoded_finding)
            return findings

        php_finding = await self._check_php_wrappers(ip)
        if php_finding:
            findings.append(php_finding)

        return findings

    async def _send_request(self, ip: InjectionPoint, payload: str):
        if ip.method == "GET":
            return await self.client.get(ip.url, params={ip.param_name: payload})
        elif ip.method == "POST":
            if ip.form_inputs:
                data = {f["name"]: "test" for f in ip.form_inputs}
                data[ip.param_name] = payload
            else:
                data = {ip.param_name: payload}
            return await self.client.post(ip.form_action or ip.url, data=data)
        else:
            return await self.client.get(ip.url, params={ip.param_name: payload})

    async def _send_raw_request(self, ip: InjectionPoint):
        if ip.method == "GET":
            return await self.client.get(ip.url, params={ip.param_name: "index"})
        elif ip.method == "POST":
            if ip.form_inputs:
                data = {f["name"]: "test" for f in ip.form_inputs}
                data[ip.param_name] = "index"
            else:
                data = {ip.param_name: "index"}
            return await self.client.post(ip.form_action or ip.url, data=data)
        else:
            return await self.client.get(ip.url, params={ip.param_name: "index"})

    def _make_finding(self, ip, payload, variant, severity, confidence, response, evidence, description, remediation):
        return Finding(
            vuln_type="path_traversal",
            severity=severity,
            confidence=confidence,
            endpoint=ip.url,
            parameter=ip.param_name,
            method=ip.method,
            payload=payload,
            payload_variant=variant,
            request_raw=self.format_request(
                ip.method, ip.url,
                dict(response.request.headers) if hasattr(response, 'request') else {},
                response.request.content.decode(errors="ignore") if hasattr(response, 'request') else payload,
            ),
            response_raw=self.format_response(response),
            response_evidence=evidence[:500],
            poc=f"curl -X {ip.method} '{ip.url}?{ip.param_name}={payload}'",
            description=description,
            remediation=remediation,
        )

    async def _check_linux_traversal(self, ip: InjectionPoint) -> Finding | None:
        payloads = get_linux_traversal()
        bypass_methods = self.waf_info.get("bypass_methods", [None])

        try:
            normal_resp = await self._send_raw_request(ip)
            normal_body = normal_resp.text
            normal_len = len(normal_body)
        except Exception:
            normal_body = ""
            normal_len = 0

        for payload_entry in payloads[:self.MAX_LINUX_PAYLOADS]:
            raw_payload = payload_entry["payload"]
            for bypass_name in bypass_methods[:1]:
                payload = raw_payload
                if bypass_name:
                    payload = apply_bypass(raw_payload, bypass_name)
                finding = await self._try_payload(
                    ip, payload, normal_body, normal_len,
                    variant=f"linux_{payload_entry.get('file', '').replace('/', '_').strip('_')}",
                    bypass_name=bypass_name,
                    target_file=payload_entry.get("file", ""),
                )
                if finding:
                    return finding
        return None

    async def _check_windows_traversal(self, ip: InjectionPoint) -> Finding | None:
        payloads = get_windows_traversal()
        bypass_methods = self.waf_info.get("bypass_methods", [None])

        try:
            normal_resp = await self._send_raw_request(ip)
            normal_body = normal_resp.text
            normal_len = len(normal_body)
        except Exception:
            normal_body = ""
            normal_len = 0

        for payload_entry in payloads[:self.MAX_WINDOWS_PAYLOADS]:
            raw_payload = payload_entry["payload"]
            for bypass_name in bypass_methods[:1]:
                payload = raw_payload
                if bypass_name:
                    payload = apply_bypass(raw_payload, bypass_name)
                finding = await self._try_payload(
                    ip, payload, normal_body, normal_len,
                    variant=f"windows_{payload_entry.get('file', '').replace('\\', '_').replace(':', '').strip('_')}",
                    bypass_name=bypass_name,
                    target_file=payload_entry.get("file", ""),
                )
                if finding:
                    return finding
        return None

    async def _check_encoded_traversal(self, ip: InjectionPoint) -> Finding | None:
        payloads = get_encoded_traversal()

        try:
            normal_resp = await self._send_raw_request(ip)
            normal_body = normal_resp.text
            normal_len = len(normal_body)
        except Exception:
            normal_body = ""
            normal_len = 0

        for payload_entry in payloads[:self.MAX_ENCODED_PAYLOADS]:
            payload = payload_entry["payload"]
            encoding = payload_entry.get("encoding", "unknown")
            finding = await self._try_payload(
                ip, payload, normal_body, normal_len,
                variant=f"encoded_{encoding}",
                bypass_name=None,
                target_file=payload_entry.get("file", ""),
            )
            if finding:
                return finding
        return None

    async def _check_php_wrappers(self, ip: InjectionPoint) -> Finding | None:
        payloads = get_php_specific()

        try:
            normal_resp = await self._send_raw_request(ip)
            normal_body = normal_resp.text
            normal_len = len(normal_body)
        except Exception:
            normal_body = ""
            normal_len = 0

        for payload_entry in payloads[:self.MAX_PHP_PAYLOADS]:
            payload = payload_entry["payload"]
            variant = payload_entry.get("variant", "php_wrapper")

            try:
                resp = await self._send_request(ip, payload)
                body = resp.text[:5000]

                if variant == "php_filter":
                    if len(body) > 100 and body != normal_body:
                        evidence = self._check_php_filter_output(body)
                        if evidence:
                            return self._make_finding(
                                ip, payload, f"php_{variant}", "high",
                                self.CONTENT_MATCH_CONFIDENCE, resp, evidence,
                                f"路径穿越（PHP Filter）：参数 `{ip.param_name}` 支持 php://filter 封装器",
                                "禁用 allow_url_include 和 allow_url_fopen",
                            )
                    if self._is_base64_content(body, normal_body):
                        return self._make_finding(
                            ip, payload, f"php_{variant}", "high",
                            self.CONTENT_MATCH_CONFIDENCE, resp,
                            f"响应疑似 base64 内容，长度 {len(body)} (正常: {normal_len})",
                            f"路径穿越（PHP Filter）：参数 `{ip.param_name}` 返回 base64 数据",
                            "禁用 allow_url_include",
                        )
                elif variant in ("php_input", "expect", "phar"):
                    if body != normal_body and len(body) > 10:
                        category, pattern = match_file_content(body)
                        if category and category != "error_messages":
                            return self._make_finding(
                                ip, payload, f"php_{variant}", "high",
                                self.CONTENT_MATCH_CONFIDENCE, resp,
                                f"PHP 封装器匹配: {pattern}",
                                f"路径穿越（PHP 封装器）：参数 `{ip.param_name}` 支持 {variant}",
                                "禁用不必要的 PHP 流封装器",
                            )
                        elif self._check_file_error(body, normal_body):
                            return self._make_finding(
                                ip, payload, f"php_{variant}_error", "medium",
                                self.ERROR_BASED_CONFIDENCE, resp,
                                f"PHP 封装器错误: {body[:300]}",
                                f"路径穿越（PHP 封装器 Error）：参数 `{ip.param_name}` 触发文件错误",
                                "禁用 allow_url_include，配置 open_basedir",
                            )
            except Exception:
                continue
        return None

    def _is_base64_content(self, body: str, normal_body: str) -> bool:
        if len(body) < 20 or body == normal_body:
            return False
        b64_set = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
        non_ws = [c for c in body.strip()[:200] if not c.isspace()]
        if len(non_ws) < 10:
            return False
        ratio = sum(1 for c in non_ws[:100] if c in b64_set) / min(len(non_ws), 100)
        has_html = "<html" in body.lower() or "<div" in body.lower()
        return ratio > 0.85 and not has_html

    def _check_php_filter_output(self, body: str) -> str | None:
        import base64
        try:
            cleaned = body.strip().replace("\n", "").replace("\r", "").replace(" ", "")
            if len(cleaned) > 20:
                decoded = base64.b64decode(cleaned).decode("utf-8", errors="ignore")
                if "<?php" in decoded or "<?=" in decoded:
                    return f"Base64 解码含 PHP 源码: {decoded[:200]}"
        except Exception:
            pass
        return None

    async def _try_payload(self, ip, payload, normal_body, normal_len, variant, bypass_name, target_file=""):
        full_variant = f"{variant}_bypass_{bypass_name}" if bypass_name else variant

        try:
            resp = await self._send_request(ip, payload)
            body = resp.text[:5000]

            category, pattern = match_file_content(body)
            if category and category != "error_messages":
                return self._make_finding(
                    ip, payload, full_variant, "high",
                    self.CONTENT_MATCH_CONFIDENCE, resp,
                    f"文件内容匹配: {category}, 特征={pattern}, 长度={len(body)} (正常={normal_len})",
                    f"路径穿越：参数 `{ip.param_name}` 可读取 `{target_file or category}`，匹配 `{pattern}`",
                    "使用白名单校验文件路径参数，禁止 ../ 等穿越字符",
                )

            if self._check_file_error(body, normal_body):
                return self._make_finding(
                    ip, payload, f"{full_variant}_error", "medium",
                    self.ERROR_BASED_CONFIDENCE, resp,
                    f"文件包含错误: {body[:300]}",
                    f"路径穿越（Error）：参数 `{ip.param_name}` 触发文件包含错误",
                    "使用间接引用如 ID 映射替代直接文件路径",
                )

            if resp.status_code == 200 and body != normal_body:
                diff = abs(len(body) - normal_len)
                if normal_len > 0 and diff > max(normal_len * 0.3, 200):
                    return self._make_finding(
                        ip, payload, f"{full_variant}_length", "low",
                        self.ERROR_BASED_CONFIDENCE, resp,
                        f"响应长度异常: {len(body)} vs {normal_len} (差 {diff})",
                        f"路径穿越（疑似）：参数 `{ip.param_name}` 响应长度异常",
                        "限制文件路径参数，使用白名单或 ID 映射",
                    )
        except Exception:
            pass
        return None

    def _check_file_error(self, body: str, normal_body: str) -> bool:
        if body == normal_body:
            return False
        indicators = [
            "failed to open stream", "No such file or directory",
            "include(", "require(", "failed opening",
            "open_basedir restriction", "Warning: include",
            "Warning: require", "Fatal error:",
        ]
        body_lower = body.lower()
        return any(ind.lower() in body_lower for ind in indicators)
