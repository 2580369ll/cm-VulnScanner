"""命令注入检测插件

检测方法:
1. Time-based   — 注入 sleep/ping 延迟命令，对比基线响应时间
2. Output-based — 注入 id/whoami 等命令，检查响应中是否出现 OS 用户信息
3. Error-based  — 注入特殊字符触发命令错误

输出检测（置信度 0.85）的优先级高于时间检测（置信度 0.65），
因为输出检测能直接证明命令执行，而时间延迟可能由网络波动引起。
"""

import re
import time

import httpx

from app.scanner.plugins.base import BasePlugin, InjectionPoint, Finding
from app.scanner.payloads.command_injection_payloads import (
    get_time_payloads,
    get_output_payloads,
    get_error_probes,
    get_linux_operators,
    get_windows_operators,
    get_output_patterns,
    get_error_patterns,
    match_output_pattern,
    match_error_pattern,
    detect_os_from_output,
)
from app.scanner.bypass import apply_bypass


class CommandInjectionPlugin(BasePlugin):
    """命令注入检测插件"""

    name = "command_injection"
    vuln_type = "command_injection"

    # 置信度阈值
    OUTPUT_CONFIDENCE = 0.85
    TIME_CONFIDENCE = 0.65
    ERROR_CONFIDENCE = 0.60

    # 时间检测阈值比例（实际延迟需超过 基线 + expected_delay * 此比例）
    TIME_THRESHOLD_RATIO = 0.8

    async def check(self, ip: InjectionPoint) -> list[Finding]:
        findings = []

        # 1) Output-based 检测（最高置信度）
        output_finding = await self._check_output_based(ip)
        if output_finding:
            findings.append(output_finding)
            return findings

        # 2) Time-based 检测
        time_finding = await self._check_time_based(ip)
        if time_finding:
            findings.append(time_finding)
            return findings

        # 3) Error-based 检测（最低置信度，仅作辅助）
        error_finding = await self._check_error_based(ip)
        if error_finding:
            findings.append(error_finding)

        return findings

    # ─── 请求发送工具方法 ───────────────────────────────────────

    async def _send_request(self, ip: InjectionPoint, payload: str):
        """向注入点发送带 payload 的请求"""
        if ip.method == "GET":
            return await self.client.get(
                ip.url,
                params={ip.param_name: payload},
            )
        elif ip.method == "POST":
            if ip.form_inputs:
                data = {f["name"]: "test" for f in ip.form_inputs}
                data[ip.param_name] = payload
            else:
                data = {ip.param_name: payload}
            return await self.client.post(
                ip.form_action or ip.url,
                data=data,
            )
        else:
            return await self.client.get(
                ip.url,
                params={ip.param_name: payload},
            )

    async def _send_raw_request(self, ip: InjectionPoint):
        """发送无 payload 的请求（用于基线测量和对比）"""
        if ip.method == "GET":
            return await self.client.get(
                ip.url,
                params={ip.param_name: "normal_test_value"},
            )
        elif ip.method == "POST":
            if ip.form_inputs:
                data = {f["name"]: "test" for f in ip.form_inputs}
                data[ip.param_name] = "normal_test_value"
            else:
                data = {ip.param_name: "normal_test_value"}
            return await self.client.post(
                ip.form_action or ip.url,
                data=data,
            )
        else:
            return await self.client.get(
                ip.url,
                params={ip.param_name: "normal_test_value"},
            )

    def _make_finding(
        self,
        ip: InjectionPoint,
        payload: str,
        variant: str,
        severity: str,
        confidence: float,
        response,
        evidence: str,
        description: str,
        remediation: str,
    ) -> Finding:
        """构建 Finding 对象"""
        return Finding(
            vuln_type="command_injection",
            severity=severity,
            confidence=confidence,
            endpoint=ip.url,
            parameter=ip.param_name,
            method=ip.method,
            payload=payload,
            payload_variant=variant,
            request_raw=self.format_request(
                ip.method,
                ip.url,
                dict(response.request.headers) if hasattr(response, 'request') else {},
                response.request.content.decode(errors="ignore") if hasattr(response, 'request') else payload,
            ),
            response_raw=self.format_response(response),
            response_evidence=evidence[:500],
            poc=f"curl -X {ip.method} '{ip.url}?{ip.param_name}={payload}'",
            description=description,
            remediation=remediation,
        )

    # ─── Output-based 检测 ──────────────────────────────────────

    async def _check_output_based(self, ip: InjectionPoint) -> Finding | None:
        """Output-based 命令注入检测

        将 id/whoami 等命令注入参数，检查响应中是否出现
        OS 用户信息的特征字符串（uid=, gid=, nt authority 等）。
        """
        output_payloads = get_output_payloads()
        linux_operators = get_linux_operators()
        windows_operators = get_windows_operators()
        bypass_methods = self.waf_info.get("bypass_methods", [None])

        # 先获取正常响应作为基线
        try:
            normal_resp = await self._send_raw_request(ip)
            normal_body = normal_resp.text[:5000]
        except Exception:
            normal_body = ""

        for cmd_entry in output_payloads[:6]:  # 限制数量避免过载
            cmd = cmd_entry["payload"]
            target_os = cmd_entry.get("os", "both")

            # 根据目标 OS 选择操作符
            operators = linux_operators + windows_operators

            for op in operators[:6]:  # 取前6个最常用的操作符
                raw_payload = f"{op}{cmd}"

                for bypass_name in bypass_methods[:1]:
                    payload = raw_payload
                    if bypass_name:
                        payload = apply_bypass(raw_payload, bypass_name)

                    try:
                        resp = await self._send_request(ip, payload)
                        body = resp.text[:5000]

                        # 检查响应中是否出现命令输出特征
                        os_type, matched_pattern = match_output_pattern(body)

                        if matched_pattern and body != normal_body:
                            variant = f"output_{cmd}"
                            if bypass_name:
                                variant += f"_{bypass_name}"
                            os_label = os_type or "unknown"

                            return self._make_finding(
                                ip=ip,
                                payload=payload,
                                variant=variant,
                                severity="critical",
                                confidence=self.OUTPUT_CONFIDENCE,
                                response=resp,
                                evidence=f"命令输出检测: 在响应中发现 {os_label} 特征 `{matched_pattern}`\n"
                                          f"Payload: {payload}\n"
                                          f"响应片段: {body[:300]}",
                                description=f"命令注入（Output-based）：参数 `{ip.param_name}` 执行了 `{cmd}` 命令，"
                                            f"响应中出现 {os_label} 用户信息。注入操作符: `{op}`",
                                remediation="使用 escapeshellcmd() 或 escapeshellarg() 过滤参数，"
                                            "避免将用户输入直接传入 system()/exec()/shell_exec() 等函数，"
                                            "优先使用白名单参数校验",
                            )
                    except Exception:
                        continue

        return None

    # ─── Time-based 检测 ────────────────────────────────────────

    async def _check_time_based(self, ip: InjectionPoint) -> Finding | None:
        """Time-based 命令注入检测

        发送 sleep/ping 延迟命令，对比基线响应时间。
        如果实际延迟超过基线 + expected_delay * threshold，判定为存在注入。
        """
        time_payloads = get_time_payloads()
        linux_operators = get_linux_operators()
        windows_operators = get_windows_operators()
        bypass_methods = self.waf_info.get("bypass_methods", [None])

        # 多次采样测量基线响应时间
        baseline = await self._measure_baseline(ip, samples=3)

        # 根据目标 OS 对负载排序: 先 Linux，后 Windows
        all_operators = (linux_operators + windows_operators)[:8]

        for tp_entry in time_payloads[:6]:
            cmd = tp_entry["payload"]
            cmd_os = tp_entry.get("os", "linux")
            expected_delay = tp_entry.get("delay", 5)

            # 选择对应 OS 的操作符
            if cmd_os == "windows":
                operators = windows_operators
            else:
                operators = linux_operators

            for op in operators[:4]:
                raw_payload = f"{op}{cmd}"

                for bypass_name in bypass_methods[:1]:
                    payload = raw_payload
                    if bypass_name:
                        payload = apply_bypass(raw_payload, bypass_name)

                    try:
                        start = time.time()
                        resp = await self._send_request(ip, payload)
                        elapsed = time.time() - start

                        # 判断延迟是否显著
                        threshold = baseline + expected_delay * self.TIME_THRESHOLD_RATIO
                        if elapsed > threshold:
                            variant = f"time_{cmd_os}"
                            if bypass_name:
                                variant += f"_{bypass_name}"

                            return self._make_finding(
                                ip=ip,
                                payload=payload,
                                variant=variant,
                                severity="high",
                                confidence=self.TIME_CONFIDENCE,
                                response=resp,
                                evidence=f"时间延迟异常: 基线 {baseline:.2f}s, "
                                          f"注入后 {elapsed:.2f}s, "
                                          f"预期延迟 {expected_delay}s, "
                                          f"阈值 {threshold:.2f}s",
                                description=f"命令注入（Time-based）：参数 `{ip.param_name}` 注入 `{cmd}` "
                                            f"后响应延迟 {elapsed:.1f}s（基线: {baseline:.1f}s），"
                                            f"操作符: `{op}`",
                                remediation="使用白名单参数校验，避免将用户输入直接拼接到系统命令中",
                            )
                    except Exception:
                        continue

        return None

    async def _measure_baseline(self, ip: InjectionPoint, samples: int = 3) -> float:
        """多次采样测量基线响应时间，取平均值"""
        total = 0.0
        count = 0

        for _ in range(samples):
            try:
                start = time.time()
                await self._send_raw_request(ip)
                elapsed = time.time() - start
                total += elapsed
                count += 1
                # 短暂间隔避免请求过快
                await self._sleep_short()
            except Exception:
                continue

        if count == 0:
            return 1.0  # 默认基线

        return total / count

    async def _sleep_short(self):
        """短暂延迟"""
        import asyncio
        await asyncio.sleep(0.1)

    # ─── Error-based 检测 ───────────────────────────────────────

    async def _check_error_based(self, ip: InjectionPoint) -> Finding | None:
        """Error-based 命令注入检测

        发送可能触发错误的特殊字符或无效命令，
        检查响应中是否出现命令错误特征。
        """
        error_probes = get_error_probes()
        error_patterns = get_error_patterns()
        operators = get_linux_operators() + get_windows_operators()
        bypass_methods = self.waf_info.get("bypass_methods", [None])

        # 先获取正常响应作为对比
        try:
            normal_resp = await self._send_raw_request(ip)
            normal_body = normal_resp.text[:5000]
        except Exception:
            normal_body = ""

        for probe in error_probes[:4]:
            probe_payload = probe["payload"]

            # 对于无效命令探测，在前面加上操作符
            if probe["type"] == "nonexistent":
                for op in operators[:3]:
                    raw_payload = f"{op}{probe_payload}"
                    finding = await self._try_error_probe(
                        ip, raw_payload, error_patterns, normal_body, bypass_methods
                    )
                    if finding:
                        return finding
            else:
                finding = await self._try_error_probe(
                    ip, probe_payload, error_patterns, normal_body, bypass_methods
                )
                if finding:
                    return finding

        return None

    async def _try_error_probe(
        self,
        ip: InjectionPoint,
        payload: str,
        error_patterns: dict,
        normal_body: str,
        bypass_methods: list,
    ) -> Finding | None:
        """尝试单个 error probe"""
        for bypass_name in bypass_methods[:1]:
            final_payload = payload
            if bypass_name:
                final_payload = apply_bypass(payload, bypass_name)

            try:
                resp = await self._send_request(ip, final_payload)
                body = resp.text[:5000]

                # 检查响应体是否有变化
                if body == normal_body:
                    continue

                os_type, matched_pattern = match_error_pattern(body)
                if matched_pattern:
                    variant = "error"
                    if bypass_name:
                        variant += f"_{bypass_name}"

                    return self._make_finding(
                        ip=ip,
                        payload=final_payload,
                        variant=variant,
                        severity="medium",
                        confidence=self.ERROR_CONFIDENCE,
                        response=resp,
                        evidence=f"命令错误特征: `{matched_pattern}`\n响应片段: {body[:300]}",
                        description=f"命令注入（Error-based）：参数 `{ip.param_name}` 触发命令错误，"
                                    f"响应中出现 `{matched_pattern}` 特征",
                        remediation="对用户输入使用 escapeshellarg() 过滤，或改用 pcntl_exec() 等安全替代方案",
                    )
            except Exception:
                continue

        return None
