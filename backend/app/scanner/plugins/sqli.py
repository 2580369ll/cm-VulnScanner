"""SQL 注入检测插件

检测方法:
1. Error-based    — 发送特殊字符触发数据库错误
2. Boolean-based  — 比较 TRUE/FALSE 条件响应差异
3. Time-based     — 检测时间延迟
4. Union-based    — UNION SELECT 列数探测
"""

import re
import time

import httpx

from app.scanner.plugins.base import BasePlugin, InjectionPoint, Finding
from app.scanner.payloads.sqli_payloads import (
    get_error_probes,
    get_boolean_payloads,
    get_time_payloads,
    get_union_payloads,
    detect_db_type,
)
from app.scanner.bypass.encoder import apply_encoder
from app.scanner.bypass.tamper import apply_tamper


class SQLiPlugin(BasePlugin):
    """SQL 注入检测插件"""

    name = "sqli"
    vuln_type = "sqli"

    async def check(self, ip: InjectionPoint) -> list[Finding]:
        findings = []

        # 构建基础请求参数
        params = self._build_params(ip)

        # 1) Error-based 探测
        error_finding = await self._check_error_based(ip, params)
        if error_finding:
            findings.append(error_finding)
            return findings  # 已确认漏洞，无需继续

        # 2) Boolean-based 盲注
        bool_finding = await self._check_boolean_based(ip, params)
        if bool_finding:
            findings.append(bool_finding)
            return findings

        # 3) Time-based 盲注
        time_finding = await self._check_time_based(ip, params)
        if time_finding:
            findings.append(time_finding)
            return findings

        # 4) Union-based
        union_finding = await self._check_union_based(ip, params)
        if union_finding:
            findings.append(union_finding)

        return findings

    def _build_params(self, ip: InjectionPoint) -> dict:
        """构建请求参数"""
        if ip.method == "GET":
            return {"params": {ip.param_name: "PLACEHOLDER"}}
        elif ip.method == "POST":
            if ip.form_inputs:
                data = {f["name"]: "test" for f in ip.form_inputs}
                data[ip.param_name] = "PLACEHOLDER"
                return {"data": data}
            return {"data": {ip.param_name: "PLACEHOLDER"}}
        return {"params": {ip.param_name: "PLACEHOLDER"}}

    def _inject_payload(self, params: dict, payload: str) -> dict:
        """将 Payload 注入到请求参数中"""
        injected = {}
        for key, value in params.items():
            if isinstance(value, dict):
                injected[key] = {
                    k: payload if v == "PLACEHOLDER" else v
                    for k, v in value.items()
                }
            else:
                injected[key] = value
        return injected

    async def _send_request(self, ip: InjectionPoint, params: dict):
        """发送 HTTP 请求"""
        method = ip.method.upper()
        url = ip.url

        if method == "GET":
            resp = await self.client.get(url, params=params.get("params", {}))
        else:
            resp = await self.client.post(
                ip.form_action or url,
                data=params.get("data", {}),
            )

        return resp

    async def _check_error_based(self, ip: InjectionPoint, params: dict) -> Finding | None:
        """Error-based 检测"""
        probes = get_error_probes()

        for probe in probes[:6]:  # 前6个基础探测
            for tamper_name in self.waf_info.get("bypass_methods", [None])[:2]:
                payload = probe["payload"]
                if tamper_name:
                    payload = apply_tamper(payload, tamper_name)

                injected = self._inject_payload(params, payload)
                try:
                    resp = await self._send_request(ip, injected)
                    body = resp.text[:5000]

                    # 检测数据库错误信息
                    db_type = detect_db_type(body)
                    if db_type:
                        return Finding(
                            vuln_type="sqli",
                            severity="high",
                            endpoint=ip.url,
                            parameter=ip.param_name,
                            method=ip.method,
                            payload=payload,
                            payload_variant=tamper_name or "raw",
                            request_raw=self.format_request(
                                ip.method, ip.url,
                                dict(resp.request.headers),
                                resp.request.content.decode(errors="ignore"),
                            ),
                            response_raw=self.format_response(resp),
                            response_evidence=body[:500],
                            poc=f"curl -X {ip.method} '{ip.url}?{ip.param_name}={payload}'",
                            description=f"Error-based SQL 注入：参数 `{ip.param_name}` 触发 {db_type} 数据库错误",
                            remediation="使用参数化查询(Prepared Statements)，对输入进行严格白名单校验",
                        )
                except Exception:
                    continue

        return None

    async def _check_boolean_based(self, ip: InjectionPoint, params: dict) -> Finding | None:
        """Boolean-based 盲注检测"""
        bool_payloads = get_boolean_payloads()

        for pair_idx in range(0, len(bool_payloads) - 1, 2):
            true_payload = bool_payloads[pair_idx]
            false_payload = bool_payloads[pair_idx + 1]

            if true_payload["expected"] != True or false_payload["expected"] != False:
                continue

            # 应用 tamper
            for tamper_name in self.waf_info.get("bypass_methods", [None])[:2]:
                tp = true_payload["payload"]
                fp = false_payload["payload"]
                if tamper_name:
                    tp = apply_tamper(tp, tamper_name)
                    fp = apply_tamper(fp, tamper_name)

                try:
                    true_params = self._inject_payload(params, tp)
                    false_params = self._inject_payload(params, fp)

                    resp_true = await self._send_request(ip, true_params)
                    resp_false = await self._send_request(ip, false_params)

                    # 比较响应差异
                    diff_ratio = self._response_diff(resp_true.text, resp_false.text)
                    status_diff = resp_true.status_code != resp_false.status_code
                    length_diff = abs(len(resp_true.text) - len(resp_false.text)) > 50

                    if status_diff or length_diff or diff_ratio > 0.05:
                        return Finding(
                            vuln_type="sqli",
                            severity="high",
                            endpoint=ip.url,
                            parameter=ip.param_name,
                            method=ip.method,
                            payload=tp,
                            payload_variant=tamper_name or "raw",
                            request_raw=self.format_request(
                                ip.method, ip.url,
                                dict(resp_true.request.headers),
                                resp_true.request.content.decode(errors="ignore"),
                            ),
                            response_raw=self.format_response(resp_true),
                            response_evidence=f"TRUE 条件响应长度: {len(resp_true.text)}, FALSE 条件响应长度: {len(resp_false.text)}, 差异率: {diff_ratio:.2%}",
                            poc=f"# Boolean-based盲注\ncurl -X {ip.method} '{ip.url}?{ip.param_name}={tp}'",
                            description=f"Boolean-based 盲注：参数 `{ip.param_name}` 在 TRUE/FALSE 条件下返回不同响应",
                            remediation="使用参数化查询，禁止拼接 SQL 语句",
                        )
                except Exception:
                    continue

        return None

    async def _check_time_based(self, ip: InjectionPoint, params: dict) -> Finding | None:
        """Time-based 盲注检测"""
        time_payloads = get_time_payloads()

        # 先测基线响应时间
        try:
            start = time.time()
            await self._send_request(ip, params)
            baseline = time.time() - start
        except Exception:
            baseline = 1.0

        for tp in time_payloads[:4]:
            payload = tp["payload"]
            expected_delay = tp.get("delay", 5)

            for tamper_name in self.waf_info.get("bypass_methods", [None])[:1]:
                if tamper_name:
                    payload = apply_tamper(payload, tamper_name)

                injected = self._inject_payload(params, payload)
                try:
                    start = time.time()
                    resp = await self._send_request(ip, injected)
                    elapsed = time.time() - start

                    # 如果响应时间显著大于基线
                    if elapsed > baseline + expected_delay * 0.7:
                        return Finding(
                            vuln_type="sqli",
                            severity="critical",
                            endpoint=ip.url,
                            parameter=ip.param_name,
                            method=ip.method,
                            payload=payload,
                            payload_variant=tamper_name or "raw",
                            request_raw=self.format_request(
                                ip.method, ip.url,
                                dict(resp.request.headers),
                                resp.request.content.decode(errors="ignore"),
                            ),
                            response_raw=self.format_response(resp),
                            response_evidence=f"响应延迟 {elapsed:.1f}s (基线: {baseline:.2f}s, 预期: {expected_delay}s)",
                            poc=f"# Time-based盲注\ncurl -X {ip.method} '{ip.url}?{ip.param_name}={payload}'",
                            description=f"Time-based 盲注：参数 `{ip.param_name}` 注入 SLEEP 函数后响应延迟 {elapsed:.1f} 秒",
                            remediation="使用参数化查询，禁止直接拼接用户输入到 SQL 语句",
                        )
                except Exception:
                    continue

        return None

    async def _check_union_based(self, ip: InjectionPoint, params: dict) -> Finding | None:
        """Union-based 检测"""
        union_payloads = get_union_payloads()

        for up in union_payloads[:5]:
            payload = up["payload"]
            columns = up.get("columns", 1)

            injected = self._inject_payload(params, payload)
            try:
                resp = await self._send_request(ip, injected)
                body = resp.text

                # 检测 UNION 成功标志
                # 通常 UNION 注入成功会在页面中出现重复行或数据泄露
                union_indicators = [
                    "UNION",
                    "NULL",
                ]

                if any(ind in body for ind in union_indicators):
                    # 进一步确认：如果页面结构和普通请求不同
                    normal_params = self._inject_payload(params, "normal_value_12345")
                    normal_resp = await self._send_request(ip, normal_params)

                    if abs(len(body) - len(normal_resp.text)) > 100:
                        return Finding(
                            vuln_type="sqli",
                            severity="critical",
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
                            response_evidence=f"UNION 注入后页面长度变化: {len(normal_resp.text)} → {len(body)}",
                            poc=f"# Union-based注入\ncurl -X {ip.method} '{ip.url}?{ip.param_name}={payload}'",
                            description=f"Union-based SQL 注入：参数 `{ip.param_name}` 支持 UNION 查询，已确认 {columns} 列",
                            remediation="使用参数化查询，禁用 UNION 拼接",
                        )
            except Exception:
                continue

        return None

    def _response_diff(self, text1: str, text2: str) -> float:
        """计算两个响应文本的差异比率"""
        if not text1 or not text2:
            return 1.0

        # 简单差异算法：按行比较
        lines1 = set(text1.split("\n"))
        lines2 = set(text2.split("\n"))

        if not lines1 and not lines2:
            return 0.0

        intersection = len(lines1 & lines2)
        union = len(lines1 | lines2)

        if union == 0:
            return 0.0

        return 1.0 - (intersection / union)
