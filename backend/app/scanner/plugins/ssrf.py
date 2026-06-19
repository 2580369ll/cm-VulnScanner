"""SSRF 服务端请求伪造检测插件

检测方法:
1. Cloud Metadata 探测 — 注入云元数据端点，检测响应中是否包含实例信息
2. 内部服务探测 — 注入内网服务 URL，检测响应中是否包含服务 Banner
3. 协议走私探测 — 注入 file/gopher/dict 协议，检测文件内容或服务响应
4. 端口探测 — 注入常见内网端口，通过响应差异判断服务存在性
5. 盲 SSRF — 通过超时差异、Collaborator 回连检测不返回结果的 SSRF
"""

import re
from urllib.parse import urlparse

import httpx

from app.scanner.plugins.base import BasePlugin, InjectionPoint, Finding
from app.scanner.payloads.ssrf_payloads import (
    get_ssrf_payloads,
    get_cloud_metadata_urls,
    get_internal_service_urls,
    get_protocol_smuggling_urls,
    get_bypass_domain_urls,
    detect_cloud_metadata,
    detect_internal_service,
    detect_file_read,
)


class SSRFPlugin(BasePlugin):
    """SSRF 检测插件"""

    name = "ssrf"
    vuln_type = "ssrf"

    async def check(self, ip: InjectionPoint) -> list[Finding]:
        findings = []

        # SSRF 只检测 query / body 类型的参数
        if ip.param_type not in ("query", "body"):
            return findings

        # 1) Cloud Metadata 探测
        cloud_finding = await self._check_cloud_metadata(ip)
        if cloud_finding:
            findings.append(cloud_finding)
            return findings

        # 2) 内部服务探测
        service_finding = await self._check_internal_services(ip)
        if service_finding:
            findings.append(service_finding)
            return findings

        # 3) 协议走私探测
        smuggling_finding = await self._check_protocol_smuggling(ip)
        if smuggling_finding:
            findings.append(smuggling_finding)
            return findings

        # 4) 端口探测（盲 SSRF）
        blind_finding = await self._check_blind_ssrf(ip)
        if blind_finding:
            findings.append(blind_finding)

        return findings

    async def _send_with_ssrf_url(self, ip: InjectionPoint, ssrf_url: str) -> httpx.Response | None:
        """向参数注入 SSRF URL 并发送请求

        Args:
            ip: 注入点信息
            ssrf_url: 要注入的 SSRF 目标 URL

        Returns:
            HTTP 响应 或 None（请求失败）
        """
        try:
            if ip.method == "GET":
                resp = await self.client.get(
                    ip.url,
                    params={ip.param_name: ssrf_url},
                )
            else:
                # POST 请求 — 构建表单数据
                if ip.form_inputs:
                    data = {f["name"]: "test" for f in ip.form_inputs}
                    data[ip.param_name] = ssrf_url
                else:
                    data = {ip.param_name: ssrf_url}
                resp = await self.client.post(
                    ip.form_action or ip.url,
                    data=data,
                    allow_redirects=False,  # 不跟随重定向，避免被重定向到外部
                )
            return resp
        except httpx.TimeoutException:
            return None  # 超时 — 可能是盲 SSRF 特征
        except Exception:
            return None

    # ====== 1. Cloud Metadata 探测 ======

    async def _check_cloud_metadata(self, ip: InjectionPoint) -> Finding | None:
        """检测云端元数据端点访问"""
        metadata_urls = get_cloud_metadata_urls()[:8]  # 限制探测数量

        for url in metadata_urls:
            try:
                resp = await self._send_with_ssrf_url(ip, url)
                if resp is None:
                    # 超时，可能触发了内网连接
                    continue

                # 检查响应体中的云元数据特征
                result = detect_cloud_metadata(resp.text)
                if result:
                    return Finding(
                        vuln_type="ssrf",
                        severity="critical",
                        confidence=0.85,
                        endpoint=ip.url,
                        parameter=ip.param_name,
                        method=ip.method,
                        payload=url,
                        payload_variant="cloud_metadata",
                        request_raw=self.format_request(
                            ip.method, ip.url,
                            dict(resp.request.headers),
                            resp.request.content.decode(errors="ignore"),
                        ),
                        response_raw=self.format_response(resp),
                        response_evidence=result["evidence"],
                        poc=f"curl -X {ip.method} '{ip.url}?{ip.param_name}={url}'",
                        description=(
                            f"SSRF 漏洞 — 云端元数据访问：参数 `{ip.param_name}` 可被用于访问 "
                            f"{result['provider'].upper()} 云实例元数据端点，攻击者可获取 "
                            f"AK/SK 等敏感凭据并控制云资源"
                        ),
                        remediation=(
                            "1. 使用 URL 白名单，仅允许访问受信任的外部域名\n"
                            "2. 禁止访问内网 IP 段 (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16)\n"
                            "3. 禁用 file/gopher/dict 等危险协议\n"
                            "4. 使用 IMDSv2（AWS）或等同的安全增强机制"
                        ),
                    )

            except Exception:
                continue

        return None

    # ====== 2. 内部服务探测 ======

    async def _check_internal_services(self, ip: InjectionPoint) -> Finding | None:
        """检测内部服务访问"""
        service_urls = get_internal_service_urls()[:12]

        for item in service_urls:
            url = item["url"]
            service_name = item["service"]

            try:
                resp = await self._send_with_ssrf_url(ip, url)
                if resp is None:
                    continue

                # 检查响应中是否包含服务特征
                result = detect_internal_service(resp.text)
                if result:
                    return Finding(
                        vuln_type="ssrf",
                        severity="high",
                        confidence=0.85,
                        endpoint=ip.url,
                        parameter=ip.param_name,
                        method=ip.method,
                        payload=url,
                        payload_variant="internal_service",
                        request_raw=self.format_request(
                            ip.method, ip.url,
                            dict(resp.request.headers),
                            resp.request.content.decode(errors="ignore"),
                        ),
                        response_raw=self.format_response(resp),
                        response_evidence=result["evidence"],
                        poc=f"curl -X {ip.method} '{ip.url}?{ip.param_name}={url}'",
                        description=(
                            f"SSRF 漏洞 — 内部服务探测：参数 `{ip.param_name}` 可被用于访问 "
                            f"内网 {service_name} 服务 ({item['port']} 端口)，攻击者可进一步"
                            f"利用 gopher/dict 协议进行漏洞利用"
                        ),
                        remediation=(
                            "1. 实施严格的 URL 白名单校验\n"
                            "2. 禁止请求访问内网地址和 localhost\n"
                            "3. 限制可访问的端口范围（仅允许 80/443）\n"
                            "4. 对 DNS 重绑定攻击实施防护"
                        ),
                    )

            except Exception:
                continue

        return None

    # ====== 3. 协议走私探测 ======

    async def _check_protocol_smuggling(self, ip: InjectionPoint) -> Finding | None:
        """检测协议走私（file/gopher/dict）"""
        smuggling_urls = get_protocol_smuggling_urls()[:10]

        for url in smuggling_urls:
            try:
                resp = await self._send_with_ssrf_url(ip, url)
                if resp is None:
                    # 超时可能意味着成功连接到内网但无响应
                    if url.startswith("file://") or url.startswith("gopher://"):
                        return Finding(
                            vuln_type="ssrf",
                            severity="critical",
                            confidence=0.50,
                            endpoint=ip.url,
                            parameter=ip.param_name,
                            method=ip.method,
                            payload=url,
                            payload_variant="protocol_smuggling_blind",
                            request_raw=self.format_request(
                                ip.method, ip.url,
                                {},
                                f"{ip.param_name}={url}",
                            ),
                            response_raw="",
                            response_evidence=(
                                f"注入 {url} 后请求超时/连接被拒绝，"
                                f"表明目标可能接受了该协议并尝试建立内网连接（盲 SSRF）"
                            ),
                            poc=f"curl -X {ip.method} '{ip.url}?{ip.param_name}={url}'",
                            description=(
                                f"SSRF 漏洞（协议走私 — 盲测）：参数 `{ip.param_name}` "
                                f"接受了 {url.split('://')[0]} 协议，攻击者可利用此漏洞"
                                f"探测内网服务或读取本地文件"
                            ),
                            remediation=(
                                "1. 仅允许 http/https 协议\n"
                                "2. 禁止 file/gopher/dict/ftp/netdoc/jar 等协议\n"
                                "3. 使用 DNS 解析结果白名单"
                            ),
                        )

                # 检测 file 协议响应
                if url.startswith("file://"):
                    file_result = detect_file_read(resp.text)
                    if file_result:
                        return Finding(
                            vuln_type="ssrf",
                            severity="critical",
                            confidence=0.85,
                            endpoint=ip.url,
                            parameter=ip.param_name,
                            method=ip.method,
                            payload=url,
                            payload_variant="file_protocol",
                            request_raw=self.format_request(
                                ip.method, ip.url,
                                dict(resp.request.headers),
                                resp.request.content.decode(errors="ignore"),
                            ),
                            response_raw=self.format_response(resp),
                            response_evidence=file_result["evidence"],
                            poc=f"curl -X {ip.method} '{ip.url}?{ip.param_name}=file:///etc/passwd'",
                            description=(
                                f"SSRF 漏洞 — 任意文件读取：参数 `{ip.param_name}` 支持 file:// 协议，"
                                f"攻击者可读取服务器本地文件（如 /etc/passwd），"
                                f"结合其他漏洞可实现 RCE"
                            ),
                            remediation=(
                                "1. 禁止 file:// 协议\n"
                                "2. 使用 URL Scheme 白名单\n"
                                "3. 实施 URL 解析器安全配置"
                            ),
                        )

                # 检测 gopher 协议响应（Redis）
                if url.startswith("gopher://") or url.startswith("dict://"):
                    # 检查响应中是否有 Redis 特征
                    from app.scanner.payloads.ssrf_payloads import REDIS_RESPONSE_PATTERNS
                    redis_matches = [p for p in REDIS_RESPONSE_PATTERNS if p in resp.text]
                    if redis_matches:
                        return Finding(
                            vuln_type="ssrf",
                            severity="critical",
                            confidence=0.85,
                            endpoint=ip.url,
                            parameter=ip.param_name,
                            method=ip.method,
                            payload=url,
                            payload_variant="gopher_redis",
                            request_raw=self.format_request(
                                ip.method, ip.url,
                                dict(resp.request.headers),
                                resp.request.content.decode(errors="ignore"),
                            ),
                            response_raw=self.format_response(resp),
                            response_evidence=f"Redis 响应特征: {', '.join(redis_matches[:5])}",
                            poc=f"curl -X {ip.method} '{ip.url}?{ip.param_name}={url}'",
                            description=(
                                f"SSRF 漏洞 — Gopher 协议攻击 Redis：参数 `{ip.param_name}` "
                                f"支持 gopher:// 协议，成功探测到内网 Redis 服务，"
                                f"攻击者可写入 webshell 或写 crontab 实现 RCE"
                            ),
                            remediation=(
                                "1. 禁止 gopher:// 和 dict:// 协议\n"
                                "2. Redis 配置 requirepass 认证\n"
                                "3. Redis 以低权限用户运行\n"
                                "4. 使用 rename-command 禁用危险命令 (CONFIG/FLUSHALL)"
                            ),
                        )

                # 检查状态码异常的响应（200 + 非正常 HTML）
                if (resp.status_code == 200
                        and len(resp.text) > 10
                        and "<html" not in resp.text[:200].lower()
                        and "<!doctype" not in resp.text[:200].lower()):
                    return Finding(
                        vuln_type="ssrf",
                        severity="high",
                        confidence=0.75,
                        endpoint=ip.url,
                        parameter=ip.param_name,
                        method=ip.method,
                        payload=url,
                        payload_variant="protocol_smuggling",
                        request_raw=self.format_request(
                            ip.method, ip.url,
                            dict(resp.request.headers),
                            resp.request.content.decode(errors="ignore"),
                        ),
                        response_raw=self.format_response(resp),
                        response_evidence=f"非正常 HTML 响应，状态码 {resp.status_code}，响应长度 {len(resp.text)} 字节，疑似内网服务响应",
                        poc=f"curl -X {ip.method} '{ip.url}?{ip.param_name}={url}'",
                        description=(
                            f"SSRF 漏洞 — 协议走私：参数 `{ip.param_name}` 接受 "
                            f"{url.split('://')[0]} 协议，返回非预期内容，可能存在 SSRF 漏洞"
                        ),
                        remediation=(
                            "1. 仅允许 http/https 协议\n"
                            "2. 对 URL 的 scheme 部分做严格校验"
                        ),
                    )

            except Exception:
                continue

        return None

    # ====== 4. 盲 SSRF 检测 ======

    async def _check_blind_ssrf(self, ip: InjectionPoint) -> Finding | None:
        """检测盲 SSRF（通过超时差异和响应差异）

        盲 SSRF 特征：
        - 注入内网 URL 后请求超时（正在尝试连接内网）
        - 注入不可达地址后快速返回错误（DNS 解析失败）
        - 两者响应时间/状态码有明显差异
        """
        # 测试 URL 集合
        test_urls = {
            "reachable": "http://127.0.0.1:6379/",    # Redis 端口 — 内网可达
            "unreachable": "http://192.0.2.1:9999/",    # RFC 5737 TEST-NET — 不可达
            "external": "http://example.com/",          # 正常外网（基线）
        }

        results = {}

        for label, url in test_urls.items():
            try:
                resp = await self._send_with_ssrf_url(ip, url)
                if resp is not None:
                    results[label] = {
                        "status": resp.status_code,
                        "length": len(resp.text),
                    }
                else:
                    results[label] = {"status": 0, "length": 0, "timeout": True}
            except Exception as e:
                results[label] = {"status": 0, "length": 0, "error": str(e)}

        # 判断盲 SSRF
        inner_timeout = results["reachable"].get("timeout", False)
        inner_status = results["reachable"].get("status", 0)
        unreachable_timeout = results["unreachable"].get("timeout", False)
        external_status = results["external"].get("status", 0)

        # 内网请求超时 且 不可达地址未超时 → 存在内网连接尝试
        if inner_timeout and not unreachable_timeout:
            return Finding(
                vuln_type="ssrf",
                severity="high",
                confidence=0.55,
                endpoint=ip.url,
                parameter=ip.param_name,
                method=ip.method,
                payload="http://127.0.0.1:6379/",
                payload_variant="blind_ssrf_timeout",
                request_raw=self.format_request(
                    ip.method, ip.url,
                    {},
                    f"{ip.param_name}=http://127.0.0.1:6379/",
                ),
                response_raw=f"内网请求超时，不可达地址快速返回，外部请求状态码 {external_status}",
                response_evidence=(
                    f"盲 SSRF 证据：内网地址 (127.0.0.1:6379) 请求超时 ({'是' if inner_timeout else '否'})，"
                    f"不可达地址 (192.0.2.1:9999) 超时 ({'是' if unreachable_timeout else '否'})，"
                    f"外部正常响应状态: {external_status}"
                ),
                poc=f"# 盲 SSRF 验证\n# 1. 注入内网地址 → 观察超时\ncurl -X {ip.method} '{ip.url}?{ip.param_name}=http://127.0.0.1:6379/'\n# 2. 注入不可达地址 → 快速失败\ncurl -X {ip.method} '{ip.url}?{ip.param_name}=http://192.0.2.1:9999/'",
                description=(
                    f"SSRF 漏洞（盲测）：参数 `{ip.param_name}` 在注入内网地址时出现超时，"
                    f"而在注入不可达地址时快速返回，表明服务器正在尝试连接内网资源。"
                    f"建议使用 Burp Collaborator 或 DNSLog 平台确认"
                ),
                remediation=(
                    "1. 禁止用户输入影响服务器端的网络请求目标\n"
                    "2. 实施严格的 URL 白名单\n"
                    "3. 使用内网隔离和网络策略限制出站连接"
                ),
            )

        # 内网请求返回了不同的状态码/内容长度（与正常请求差异大）
        if inner_status != external_status and inner_status > 0:
            # 进一步验证：内网请求的响应与正常请求差异显著
            diff = abs(results["reachable"].get("length", 0) - results["external"].get("length", 0))
            if diff > 100:
                return Finding(
                    vuln_type="ssrf",
                    severity="medium",
                    confidence=0.60,
                    endpoint=ip.url,
                    parameter=ip.param_name,
                    method=ip.method,
                    payload="http://127.0.0.1:6379/",
                    payload_variant="blind_ssrf_diff",
                    request_raw=self.format_request(
                        ip.method, ip.url,
                        {},
                        f"{ip.param_name}=http://127.0.0.1:6379/",
                    ),
                    response_raw=f"内网: {inner_status} ({results['reachable'].get('length', 0)}B), "
                                 f"外部: {external_status} ({results['external'].get('length', 0)}B)",
                    response_evidence=(
                        f"响应差异：内网地址状态码 {inner_status}，外部地址状态码 {external_status}，"
                        f"长度差异 {diff} 字节"
                    ),
                    poc=f"curl -X {ip.method} '{ip.url}?{ip.param_name}=http://127.0.0.1:6379/'",
                    description=(
                        f"SSRF 漏洞（可能盲测）：参数 `{ip.param_name}` 注入内网地址时返回状态码 "
                        f"{inner_status}，与正常外网请求 ({external_status}) 不同，可能需要进一步验证"
                    ),
                    remediation=(
                        "1. 对用户可控的 URL 参数进行白名单限制\n"
                        "2. 禁止访问内网 IP / localhost\n"
                        "3. 使用网络层出站过滤"
                    ),
                )

        # 不可达地址也超时（可能是网络问题，但记录为信息）
        if inner_timeout and unreachable_timeout:
            return Finding(
                vuln_type="ssrf",
                severity="info",
                confidence=0.30,
                endpoint=ip.url,
                parameter=ip.param_name,
                method=ip.method,
                payload="http://127.0.0.1:6379/",
                payload_variant="potential_ssrf",
                request_raw="",
                response_raw="",
                response_evidence=(
                    "内网和不可达地址均超时，无法确认是否为 SSRF。"
                    "建议使用 Collaborator/DNSLog 平台进一步确认"
                ),
                poc="",
                description=(
                    f"SSRF 漏洞（待确认）：参数 `{ip.param_name}` 可能用于发起后端请求，"
                    f"但无法通过超时差异确认。建议手动验证"
                ),
                remediation="如果确认为 SSRF，请实施 URL 白名单和内网访问控制",
            )

        return None
