"""IDOR (Insecure Direct Object Reference) 越权检测插件

检测方法:
1. 从目标 URL 中提取 API 路径模式，尝试常见 IDOR 端点
2. 对每个端点使用不同 ID 值 (1, 2, 3, 100, 101) 发起请求
3. 比较不同 ID 的响应 — 如果不同 ID 返回 200 且有不同数据，标记为 IDOR
4. 分析响应体中的 PII / 账户数据以确认数据泄露

置信度规则:
- 0.85: 多个 ID 返回 200 且各自包含不同的 PII 数据
- 0.75: 多个 ID 返回 200 且响应内容明显不同（长度差异 > 100 字节）
- 0.60: 两个不同 ID 返回 200 但响应长度差异较小
- 0.45: 仅一个 ID 返回 200，可能 ID 不存在

重要: 此插件测试无认证情况下访问其他用户资源的能力
"""

from urllib.parse import urljoin

import httpx

from app.scanner.plugins.base import BasePlugin, InjectionPoint, Finding
from app.scanner.payloads.idor_payloads import (
    get_idor_paths,
    get_id_values,
    get_paths_for_url,
    analyze_response_for_pii,
    analyze_response_for_order_data,
    compare_idor_responses,
)


class IDORPlugin(BasePlugin):
    """IDOR 越权检测插件"""

    name = "idor"
    vuln_type = "idor"

    # 优先探测的路径类别（按价值排序）
    PRIORITY_CATEGORIES = [
        "users",
        "accounts",
        "orders",
        "invoices",
        "documents",
        "tickets",
        "posts",
        "addresses",
        "carts",
        "subscriptions",
        "reports",
    ]

    # 每个目标最多探测的路径数
    MAX_PATHS_PER_TARGET = 30

    # 每个路径最多测试的 ID 数
    MAX_IDS_PER_PATH = 5

    async def check(self, ip: InjectionPoint) -> list[Finding]:
        """检测目标是否存在 IDOR 漏洞

        Args:
            ip: 注入点信息

        Returns:
            发现的漏洞列表
        """
        findings = []

        base_url = self._get_base_url(ip.url)
        if not base_url:
            return findings

        # 获取探测路径
        all_paths = get_idor_paths()
        test_ids = get_id_values()[:self.MAX_IDS_PER_PATH]  # [1, 2, 3, 4, 5]

        # 按优先级探测路径
        probed = 0

        # 先探测用户相关的高价值路径
        priority_paths = self._prioritize_paths(all_paths)

        for path_template in priority_paths:
            if probed >= self.MAX_PATHS_PER_TARGET:
                break

            finding = await self._check_path(base_url, path_template, test_ids, ip)
            if finding:
                findings.append(finding)
                # 发现一个 IDOR 后停止（避免过度扫描）
                if finding.confidence >= 0.75:
                    break

            probed += 1

        return findings

    async def _check_path(
        self,
        base_url: str,
        path_template: str,
        test_ids: list[int],
        ip: InjectionPoint,
    ) -> Finding | None:
        """对单个路径模板探测 IDOR

        流程:
        1. 使用多个不同 ID 值发送请求
        2. 记录所有 200 响应
        3. 比较响应中的 PII 数据差异
        4. 确认 IDOR

        Args:
            base_url: 目标基础 URL
            path_template: 路径模板 (如 /api/users/{id})
            test_ids: 测试用的 ID 列表
            ip: 原始注入点

        Returns:
            Finding 或 None
        """
        responses = {}  # {id_value: {"status": int, "body": str, "len": int, "pii": dict|None}}

        for id_val in test_ids:
            path = path_template.replace("{id}", str(id_val))
            full_url = self._build_url(base_url, path)

            try:
                resp = await self.client.get(
                    full_url,
                    follow_redirects=False,
                )

                if resp.status_code == 200:
                    body = resp.text
                    content_type = resp.headers.get("Content-Type", "")

                    pii_result = analyze_response_for_pii(body, content_type)
                    order_result = analyze_response_for_order_data(body)

                    responses[id_val] = {
                        "status": resp.status_code,
                        "body": body,
                        "len": len(body),
                        "pii": pii_result,
                        "order": order_result,
                        "url": full_url,
                        "content_type": content_type,
                    }

                    # 记录第一个成功的请求详情用于 Finding
                    if len(responses) == 1:
                        first_resp = resp

            except httpx.TimeoutException:
                continue
            except Exception:
                continue

        # 需要至少 2 个不同 ID 都返回 200
        if len(responses) < 2:
            return None

        # 比较响应差异
        id_list = list(responses.keys())
        bodies = {k: v["body"] for k, v in responses.items()}
        comparison_results = compare_idor_responses(bodies)

        if not comparison_results:
            return None

        # 判断置信度和严重度
        confidence, severity, evidence = self._evaluate_idor(
            responses, comparison_results
        )

        if confidence < 0.40:
            return None

        # 构建 Finding
        first_id = id_list[0]
        first_info = responses[first_id]
        test_url = first_info["url"]

        # 提取最有力的证据响应
        evidence_resp = first_info["body"][:3000]

        return Finding(
            vuln_type="idor",
            severity=severity,
            confidence=confidence,
            endpoint=test_url,
            parameter="{id}",
            method="GET",
            payload=f"{path_template} (IDs: {', '.join(map(str, id_list))})",
            payload_variant="id_enumeration",
            request_raw=self.format_request(
                "GET",
                test_url,
                {},
                f"GET {test_url}",
            ),
            response_raw=self._truncate_body(evidence_resp, 3000),
            response_evidence=evidence,
            poc=self._build_poc(test_url, path_template, id_list),
            description=self._build_description(path_template, responses, comparison_results),
            remediation=self._build_remediation(path_template),
        )

    def _evaluate_idor(
        self,
        responses: dict,
        comparison_results: list[dict],
    ) -> tuple[float, str, str]:
        """评估 IDOR 的置信度和严重度

        Args:
            responses: {id_value: info_dict}
            comparison_results: compare_idor_responses() 的输出

        Returns:
            (confidence, severity, evidence_text)
        """
        # 收集 PII 统计
        total_pii_a = sum(r.get("pii_a_count", 0) for r in comparison_results)
        total_pii_b = sum(r.get("pii_b_count", 0) for r in comparison_results)
        max_len_diff = max((r.get("len_diff", 0) for r in comparison_results), default=0)

        has_pii_both = any(
            r.get("pii_a_count", 0) > 0 and r.get("pii_b_count", 0) > 0
            for r in comparison_results
        )
        has_pii_any = any(
            r.get("pii_a_count", 0) > 0 or r.get("pii_b_count", 0) > 0
            for r in comparison_results
        )
        has_order_data = any(
            v.get("order") is not None for v in responses.values()
        )

        # 提取 PII 字段信息
        all_pii_fields = set()
        for info in responses.values():
            if info.get("pii") and info["pii"].get("pii_fields"):
                all_pii_fields.update(info["pii"]["pii_fields"])

        pii_fields_str = ", ".join(sorted(list(all_pii_fields))[:5]) if all_pii_fields else ""

        # 置信度判断
        if has_pii_both:
            # 多个 ID 返回不同的 PII 数据 — 高度确信
            confidence = 0.85
            severity = "high"
            evidence = (
                f"多个不同 ID 返回了 200 状态码且各自包含不同的 PII 数据。"
                f"未认证用户可以访问其他用户的敏感信息。"
                f"检测到敏感字段: {pii_fields_str}"
            )
        elif has_order_data and max_len_diff > 200:
            # 订单数据泄露
            confidence = 0.80
            severity = "high"
            evidence = (
                f"不同 ID 返回了不同的订单/发票数据（响应长度差 {max_len_diff} 字节）。"
                f"未认证用户可以查看其他用户的订单详情。"
            )
        elif max_len_diff > 500:
            # 响应长度差异显著 — 高度疑似
            confidence = 0.75
            severity = "high"
            evidence = (
                f"不同 ID 返回 200 且响应长度差异显著（最大 {max_len_diff} 字节），"
                f"表明目标未对资源访问进行身份验证和授权检查。"
                f"响应中包含用户相关特征: {pii_fields_str}" if pii_fields_str else ""
            )
        elif has_pii_any and max_len_diff > 100:
            # 至少一个响应包含 PII
            confidence = 0.70
            severity = "medium"
            evidence = (
                f"不同 ID 返回 200，至少一个响应包含 PII 数据"
                f"（长度差异 {max_len_diff} 字节）。"
                f"敏感字段: {pii_fields_str}"
            )
        elif max_len_diff > 100:
            # 纯长度差异
            confidence = 0.60
            severity = "medium"
            evidence = (
                f"不同 ID 返回 200 但响应长度不同（最大 {max_len_diff} 字节），"
                f"可能返回了不同资源的数据。建议人工验证是否存在越权。"
            )
        elif max_len_diff > 10:
            # 微小差异 — 低置信度
            confidence = 0.45
            severity = "low"
            evidence = (
                f"多个 ID 返回 200 但响应内容差异较小"
                f"（最大 {max_len_diff} 字节），可能是时间戳或 CSRF token 差异。"
                f"建议人工确认。"
            )
        else:
            confidence = 0.30
            severity = "info"
            evidence = "多个 ID 返回 200 但响应几乎相同，不太可能是 IDOR。"

        return confidence, severity, evidence

    def _get_base_url(self, url: str) -> str:
        """从 URL 中提取基础 URL"""
        if not url:
            return ""
        return url.rstrip("/") if url.endswith("/") else url

    def _build_url(self, base_url: str, path: str) -> str:
        """拼接基础 URL 和路径"""
        if path.startswith("http://") or path.startswith("https://"):
            return path
        if path.startswith("/"):
            return f"{base_url}{path}"
        return urljoin(f"{base_url}/", path)

    def _prioritize_paths(self, paths: list[str]) -> list[str]:
        """按价值优先级排序探测路径

        高优先级:
        - 用户相关 (users/profile)
        - 账户相关 (accounts)
        - 订单相关 (orders)
        - 发票 (invoices)
        """

        def priority_score(path: str) -> int:
            path_lower = path.lower()
            score = 0

            if "/users/" in path_lower or "/user/" in path_lower:
                score += 100
            if "profile" in path_lower:
                score += 90
            if "/accounts/" in path_lower or "/account/" in path_lower:
                score += 85
            if "/orders/" in path_lower or "/order/" in path_lower:
                score += 80
            if "/invoices/" in path_lower or "/invoice/" in path_lower:
                score += 75
            if "/payments/" in path_lower or "/payment/" in path_lower:
                score += 70
            if "/documents/" in path_lower or "/document/" in path_lower:
                score += 60
            if "/tickets/" in path_lower or "/ticket/" in path_lower:
                score += 55
            if "/messages/" in path_lower or "/message/" in path_lower:
                score += 50
            if "/posts/" in path_lower or "/post/" in path_lower:
                score += 40
            if "/files/" in path_lower or "/file/" in path_lower:
                score += 35
            if "/carts/" in path_lower or "/cart/" in path_lower:
                score += 30

            return -score

        return sorted(paths, key=priority_score)

    def _build_poc(self, test_url: str, path_template: str, id_list: list[int]) -> str:
        """构建 PoC 命令"""
        id_a = id_list[0]
        id_b = id_list[-1]
        paths = [
            f"# IDOR PoC — {path_template}",
            f"# 使用不同 ID 请求同一路径，均返回 200 且包含不同用户数据",
        ]
        for id_val in id_list[:5]:
            url = test_url.replace(f"/{id_a}/", f"/{id_val}/") if f"/{id_a}/" in test_url else test_url.replace(str(id_a), str(id_val))
            paths.append(f"curl '{url}'")

        paths.append("")
        paths.append(f"# 验证: 比较 ID={id_a} 和 ID={id_b} 的响应，确认返回了不同用户的数据")

        return "\n".join(paths)

    def _build_description(
        self,
        path_template: str,
        responses: dict,
        comparison_results: list[dict],
    ) -> str:
        """构建漏洞描述"""
        id_list = sorted(responses.keys())
        pii_fields = set()

        for info in responses.values():
            if info.get("pii") and info["pii"].get("pii_fields"):
                pii_fields.update(info["pii"]["pii_fields"])

        desc_parts = [
            f"IDOR (Insecure Direct Object Reference) 越权漏洞：",
            f"路径 `{path_template}` 未进行身份验证和授权检查，",
            f"攻击者可以通过枚举 ID 参数（{', '.join(map(str, id_list))}）",
            f"访问其他用户的资源。",
        ]

        if pii_fields:
            desc_parts.append(
                f"响应中包含敏感个人信息: {', '.join(sorted(list(pii_fields))[:8])}"
            )

        desc_parts.append(
            f"共发现 {len(responses)} 个可访问的不同 ID，"
            f"所有请求均返回 200 OK。"
        )

        return "".join(desc_parts)

    def _build_remediation(self, path_template: str) -> str:
        """构建修复建议"""
        return (
            f"1. 对所有 `{path_template}` 类接口实施身份验证和授权检查\n"
            "2. 使用当前登录用户的身份来过滤数据，而非信任客户端传入的 ID\n"
            "3. 实施基于角色的访问控制 (RBAC)，确保用户只能访问自己的资源\n"
            "4. 使用 UUID 或随机标识符替代可预测的递增 ID\n"
            "5. 添加间接引用映射 (IDOR Reference Map)，后端维护 session 到实际 ID 的映射\n"
            "--- 通用建议 ---\n"
            "- 对所有 API 端点进行权限单元测试\n"
            "- 使用自动化工具（如 Autorize / AuthMatrix）在 Burp Suite 中测试越权\n"
            "- 实施 API 网关层面的统一鉴权\n"
            "- 定期进行越权漏洞专项渗透测试"
        )

    def _truncate_body(self, body: str, max_length: int = 5000) -> str:
        """截断响应正文"""
        if len(body) <= max_length:
            return body
        return body[:max_length] + f"\n\n... [已截断，原长度 {len(body)} 字符]"
