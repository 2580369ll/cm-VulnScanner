"""SSTI (Server-Side Template Injection) 检测插件

检测方法:
1. Blind math detection — 发送 {{7*7}} 等数学表达式，检查响应中的计算结果(49)
2. Dual-confirmation  — 命中第一个后发送 {{8*8}} 交叉验证(64)，排除偶然匹配
3. Engine fingerprint — 通过错误信息和特殊输出识别具体模板引擎类型

置信度分级:
- 0.95: 双确认 (7*7→49 AND 8*8→64)
- 0.70: 单匹配 (仅第一个 Payload 命中)
- 0.50: 仅在响应中发现模板引擎错误特征
"""

import re
import time

import httpx

from app.scanner.plugins.base import BasePlugin, InjectionPoint, Finding
from app.scanner.payloads.ssti_payloads import (
    get_blind_math_payloads,
    get_confirmation_payloads,
    get_fingerprint_payloads,
    get_time_payloads,
    get_engine_error_patterns,
    detect_ssti_reflection,
    detect_engine_from_error,
    get_syntax_for_engine,
)
from app.scanner.bypass import apply_bypass


class SSTIPlugin(BasePlugin):
    """SSTI 检测插件"""

    name = "ssti"
    vuln_type = "ssti"

    # 置信度阈值
    DUAL_CONFIRMATION_CONFIDENCE = 0.95
    SINGLE_MATCH_CONFIDENCE = 0.70
    ERROR_ONLY_CONFIDENCE = 0.50

    # 时间检测配置
    TIME_THRESHOLD_RATIO = 0.8

    async def check(self, ip: InjectionPoint) -> list[Finding]:
        findings = []

        # 1) Blind math detection (双确认: 7*7→49 + 8*8→64)
        math_finding = await self._check_blind_math(ip)
        if math_finding:
            findings.append(math_finding)
            return findings

        # 2) Time-based detection
        time_finding = await self._check_time_based(ip)
        if time_finding:
            findings.append(time_finding)
            return findings

        # 3) 引擎指纹识别 (错误信息匹配)
        fingerprint_finding = await self._check_engine_fingerprint(ip)
        if fingerprint_finding:
            findings.append(fingerprint_finding)

        return findings

    # ─── 请求发送工具方法 ───────────────────────────────────────

    async def _send_request(self, ip: InjectionPoint, payload: str):
        """向注入点发送带 payload 的请求，支持 GET/POST/Header 三种注入位置"""
        param_type = ip.param_type

        # Header 注入
        if param_type == "header":
            headers = {
                ip.param_name: payload,
            }
            try:
                return await self.client.get(
                    ip.url,
                    headers=headers,
                )
            except Exception:
                # 某些头部可能被 httpx 限制，回退到 GET
                pass

        # POST 注入
        if ip.method == "POST":
            if ip.form_inputs:
                data = {f["name"]: "test" for f in ip.form_inputs}
                data[ip.param_name] = payload
            else:
                data = {ip.param_name: payload}
            return await self.client.post(
                ip.form_action or ip.url,
                data=data,
            )

        # GET 注入（默认）
        return await self.client.get(
            ip.url,
            params={ip.param_name: payload},
        )

    async def _send_raw_request(self, ip: InjectionPoint):
        """发送无 payload 的请求（用于基线对比）"""
        if ip.method == "POST":
            if ip.form_inputs:
                data = {f["name"]: "test" for f in ip.form_inputs}
                data[ip.param_name] = "normal_test_value"
            else:
                data = {ip.param_name: "normal_test_value"}
            return await self.client.post(
                ip.form_action or ip.url,
                data=data,
            )
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
        matched_engine: str = "",
    ) -> Finding:
        """构建 Finding 对象"""
        engine_info = f"\n识别引擎: {matched_engine}" if matched_engine else ""

        return Finding(
            vuln_type="ssti",
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
            response_evidence=evidence[:500] + engine_info,
            poc=f"curl -X {ip.method} '{ip.url}?{ip.param_name}={payload}'",
            description=description,
            remediation=remediation,
        )

    # ─── Blind Math 检测 (双确认) ────────────────────────────────

    async def _check_blind_math(self, ip: InjectionPoint) -> Finding | None:
        """Blind SSTI math detection with dual-confirmation

        流程:
        1. 发送 {{7*7}} 检查响应是否包含 "49"
        2. 如命中，发送 {{8*8}} 检查响应是否包含 "64"
        3. 双确认 → 置信度 0.95，单确认 → 0.70
        """
        blind_payloads = get_blind_math_payloads()
        confirm_payloads = get_confirmation_payloads()

        # 先获取正常响应作为基线对比
        try:
            normal_resp = await self._send_raw_request(ip)
            normal_body = normal_resp.text[:5000]
        except Exception:
            normal_body = ""

        # 第一阶段: 发送盲检测 Payload
        for blind_entry in blind_payloads[:4]:  # 限制4个减少请求量
            blind_payload = blind_entry["payload"]
            expected = blind_entry["expected"]
            syntax = blind_entry["syntax"]

            try:
                resp = await self._send_request(ip, blind_payload)
                body = resp.text[:5000]

                # 检查响应中是否出现预期计算结果
                if expected not in body:
                    continue

                # 响应必须有变化（排除页面本身就包含 "49" 的情况）
                if body == normal_body:
                    continue

                # 第一阶段命中 → 进行第二阶段交叉验证
                for confirm_entry in confirm_payloads:
                    confirm_payload = confirm_entry["payload"]
                    confirm_expected = confirm_entry["expected"]

                    # 选择语法兼容的确认 Payload
                    # {{8*8}} 匹配 {{ }} 语法, ${8*8} 匹配 ${ } 语法
                    if "{{" in syntax and "{{" not in confirm_payload and "${" in confirm_payload:
                        continue
                    if "${" in syntax and "${" not in confirm_payload and "{{" in confirm_payload:
                        continue

                    try:
                        resp2 = await self._send_request(ip, confirm_payload)
                        body2 = resp2.text[:5000]

                        if confirm_expected in body2 and body2 != normal_body:
                            # 双确认: 两个数学运算都正确执行
                            math_evidence = (
                                f"双确认验证通过:\n"
                                f"  Payload 1: `{blind_payload}` → 响应中出现 `{expected}`\n"
                                f"  Payload 2: `{confirm_payload}` → 响应中出现 `{confirm_expected}`\n"
                                f"  语法范围: {syntax}"
                            )

                            # 尝试识别引擎
                            reflection = detect_ssti_reflection(blind_payload, body)
                            matched_engine = reflection.get("matched_engine", "")

                            return self._make_finding(
                                ip=ip,
                                payload=f"{blind_payload} / {confirm_payload}",
                                variant="dual_confirmed_math",
                                severity="critical",
                                confidence=self.DUAL_CONFIRMATION_CONFIDENCE,
                                response=resp,
                                evidence=math_evidence,
                                description=(
                                    f"SSTI (服务端模板注入): 参数 `{ip.param_name}` 存在模板注入漏洞。"
                                    f"注入 `{blind_payload}` 时响应返回计算结果 `{expected}`，"
                                    f"注入 `{confirm_payload}` 时响应返回计算结果 `{confirm_expected}`，"
                                    f"双确认验证通过，证明模板表达式被服务端解析执行。"
                                    f"{'推测引擎: ' + matched_engine if matched_engine else ''}"
                                ),
                                remediation=(
                                    "1. 避免将用户输入直接传入模板引擎的 render() 方法\n"
                                    "2. 使用沙箱模式运行模板（如 Jinja2 SandboxedEnvironment）\n"
                                    "3. 对用户输入中的模板语法字符（{{}}、${}、#{ }）进行转义\n"
                                    "4. 考虑使用无模板语法的纯文本渲染替代方案\n"
                                    "5. 实施最小权限原则，限制模板可访问的 Python/Java 对象"
                                ),
                                matched_engine=matched_engine,
                            )

                        # 确认 Payload 未命中，但第一个 Payload 命中了 → 单匹配
                        single_evidence = (
                            f"单匹配验证:\n"
                            f"  Payload 1: `{blind_payload}` → 响应中出现 `{expected}`\n"
                            f"  Payload 2: `{confirm_payload}` → 未在响应中发现 `{confirm_expected}`\n"
                            f"  语法范围: {syntax}"
                        )

                        reflection = detect_ssti_reflection(blind_payload, body)
                        matched_engine = reflection.get("matched_engine", "")

                        return self._make_finding(
                            ip=ip,
                            payload=blind_payload,
                            variant="single_match_math",
                            severity="high",
                            confidence=self.SINGLE_MATCH_CONFIDENCE,
                            response=resp,
                            evidence=single_evidence,
                            description=(
                                f"SSTI (服务端模板注入 - 单确认): 参数 `{ip.param_name}` 注入 "
                                f"`{blind_payload}` 时响应返回计算结果 `{expected}`，"
                                f"但二次验证 Payload `{confirm_payload}` 未命中。"
                                f"可能存在部分模板解析或语法兼容性问题。"
                                f"{'推测引擎: ' + matched_engine if matched_engine else ''}"
                            ),
                            remediation=(
                                "排查参数是否被传入模板引擎，即使单次确认也应视为高危"
                            ),
                            matched_engine=matched_engine,
                        )

                    except Exception:
                        continue

            except Exception:
                continue

        return None

    # ─── Time-based 检测 ─────────────────────────────────────────

    async def _check_time_based(self, ip: InjectionPoint) -> Finding | None:
        """Time-based SSTI 检测

        注入 sleep/popen('sleep 5') 等延迟 Payload，
        对比基线响应时间判断是否执行。
        """
        time_payloads = get_time_payloads()
        bypass_methods = self.waf_info.get("bypass_methods", [None])

        # 多次采样测量基线
        baseline = await self._measure_baseline(ip, samples=3)

        for tp_entry in time_payloads[:3]:  # 限制数量
            raw_payload = tp_entry["payload"]
            engine = tp_entry["engine"]
            expected_delay = tp_entry.get("delay", 5)

            for bypass_name in bypass_methods[:1]:
                payload = raw_payload
                if bypass_name:
                    payload = apply_bypass(raw_payload, bypass_name)

                try:
                    start = time.time()
                    resp = await self._send_request(ip, payload)
                    elapsed = time.time() - start

                    threshold = baseline + expected_delay * self.TIME_THRESHOLD_RATIO
                    if elapsed > threshold:
                        variant = f"time_{engine}"
                        if bypass_name:
                            variant += f"_{bypass_name}"

                        return self._make_finding(
                            ip=ip,
                            payload=payload,
                            variant=variant,
                            severity="high",
                            confidence=self.SINGLE_MATCH_CONFIDENCE,
                            response=resp,
                            evidence=(
                                f"时间延迟异常: "
                                f"基线 {baseline:.2f}s, "
                                f"注入后 {elapsed:.2f}s, "
                                f"预期延迟 {expected_delay}s, "
                                f"阈值 {threshold:.2f}s\n"
                                f"使用的 Payload ({engine}): {payload[:100]}"
                            ),
                            description=(
                                f"SSTI (Time-based): 参数 `{ip.param_name}` 注入 "
                                f"`{engine}` 时间延迟 Payload 后响应时间从基线 "
                                f"{baseline:.1f}s 增加到 {elapsed:.1f}s，"
                                f"表明模板表达式被服务端解析并执行了 sleep 命令。"
                            ),
                            remediation=(
                                "对用户输入中的模板注入字符进行过滤或转义，"
                                "使用沙箱模式运行模板引擎"
                            ),
                            matched_engine=engine,
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
                import asyncio
                await asyncio.sleep(0.1)
            except Exception:
                continue

        if count == 0:
            return 1.0

        return total / count

    # ─── 引擎指纹识别 ────────────────────────────────────────────

    async def _check_engine_fingerprint(self, ip: InjectionPoint) -> Finding | None:
        """通过错误信息识别模板引擎

        发送可能触发模板错误的 Payload，
        根据响应中的错误特征识别引擎类型。
        仅作辅助判断（置信度较低），不单独作为漏洞确认依据。
        """
        error_patterns = get_engine_error_patterns()
        fingerprint_payloads = get_fingerprint_payloads()

        # 先获取正常响应
        try:
            normal_resp = await self._send_raw_request(ip)
            normal_body = normal_resp.text[:5000]
        except Exception:
            normal_body = ""

        for fp_entry in fingerprint_payloads[:3]:
            payload = fp_entry["payload"]

            try:
                resp = await self._send_request(ip, payload)
                body = resp.text[:5000]

                # 响应必须有变化
                if body == normal_body:
                    continue

                # 检查预期输出
                expected = fp_entry.get("expected")
                if expected and expected in body:
                    engine = fp_entry["engine"]
                    return self._make_finding(
                        ip=ip,
                        payload=payload,
                        variant=f"fingerprint_{engine}",
                        severity="medium",
                        confidence=self.ERROR_ONLY_CONFIDENCE,
                        response=resp,
                        evidence=f"引擎指纹识别: Payload `{payload}` 预期输出 `{expected}` 出现在响应中\n推测引擎: {engine}",
                        description=(
                            f"SSTI 引擎指纹: 参数 `{ip.param_name}` 注入 "
                            f"`{payload}` 后响应中出现预期输出 `{expected}`，"
                            f"推测模板引擎为 {engine}。"
                        ),
                        remediation="进一步验证并确认漏洞危害程度",
                        matched_engine=engine,
                    )

                # 检查错误特征
                detected_engine = detect_engine_from_error(body)
                if detected_engine:
                    return self._make_finding(
                        ip=ip,
                        payload=payload,
                        variant=f"engine_error_{detected_engine}",
                        severity="medium",
                        confidence=self.ERROR_ONLY_CONFIDENCE,
                        response=resp,
                        evidence=f"引擎错误识别: 响应中出现 {detected_engine} 错误特征",
                        description=(
                            f"SSTI 引擎指纹(错误): 参数 `{ip.param_name}` 注入 "
                            f"`{payload}` 后响应中出现 {detected_engine} 错误信息，"
                            f"推测模板引擎为 {detected_engine}。"
                        ),
                        remediation="确认模板引擎类型后针对性修复",
                        matched_engine=detected_engine,
                    )

            except Exception:
                continue

        # 如果所有 fingerprint Payload 都没触发，尝试用一个破坏性 Payload
        # 来触发模板引擎报错
        try:
            destructive_payload = "{{undefined_variable_xxxxx_12345}}"
            resp = await self._send_request(ip, destructive_payload)
            body = resp.text[:5000]

            if body == normal_body:
                return None

            detected_engine = detect_engine_from_error(body)
            if detected_engine:
                return self._make_finding(
                    ip=ip,
                    payload=destructive_payload,
                    variant=f"destructive_error_{detected_engine}",
                    severity="low",
                    confidence=self.ERROR_ONLY_CONFIDENCE,
                    response=resp,
                    evidence=f"引擎错误识别(破坏性): 响应中出现 {detected_engine} 错误特征",
                    description=(
                        f"SSTI 潜在风险: 参数 `{ip.param_name}` 在不存在的变量 "
                        f"注入后触发了 {detected_engine} 错误，"
                        f"表明模板引擎正在解析用户输入。"
                    ),
                    remediation="验证是否确实存在模板注入，确认后针对性修复",
                    matched_engine=detected_engine,
                )
        except Exception:
            pass

        return None
