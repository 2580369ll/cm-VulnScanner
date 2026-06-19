"""WAF (Web Application Firewall) 检测器

通过发送探测 Payload 并分析响应特征来识别目标是否部署 WAF
"""

import httpx

# WAF 特征库：响应标志 → WAF 名称
WAF_SIGNATURES = {
    # 响应头字段
    "headers": {
        "X-CDN": "阿里云CDN",
        "X-Cache-Error": "Cloudflare",
        "cf-ray": "Cloudflare",
        "X-WS-Request-Id": "云锁",
        "X-Sec-Request-ID": "长亭雷池",
        "X-Powered-By-Anquanbao": "安全宝",
        "X-Powered-By-WAF": "安全狗",
        "X-Safe-Firewall": "安全狗",
        "Mod_Security": "ModSecurity",
    },
    # 响应体关键词
    "body": {
        "aliyunwaf": "阿里云WAF",
        "cloudflare": "Cloudflare",
        "mod_security": "ModSecurity",
        "安全的护盾": "安全狗",
        "网站防火墙": "安全狗",
        "WAF/2.0": "长亭雷池",
        "chaitin": "长亭雷池",
        "safedog": "安全狗",
        "yunsuo": "云锁",
        "yundun": "阿里云盾",
    },
    # HTTP 状态码模式
    "status_codes": {
        403: "可能被WAF拦截",
        406: "ModSecurity 常见拦截码",
        501: "ModSecurity 常见拦截码",
    },
}

# WAF 对应的绕过策略映射
WAF_BYPASS_STRATEGIES = {
    "阿里云WAF": ["url_encode", "hex_encode", "space2comment", "between"],
    "阿里云CDN": ["url_encode", "double_url_encode", "space2mysql9"],
    "Cloudflare": ["unicode_encode", "size_mix", "space2comment"],
    "ModSecurity": ["url_encode", "double_url_encode", "apostrophemask", "space2comment", "equaltolike"],
    "安全狗": ["url_encode", "double_url_encode", "size_mix", "space2mysql9"],
    "云锁": ["unicode_encode", "hex_encode", "apostrophemask"],
    "长亭雷池": ["url_encode", "space2comment", "between", "equaltolike"],
}


class WAFDetector:
    """WAF 检测器"""

    # 探测 Payload：既能触发 WAF 又不至于真正攻击目标
    PROBE_PAYLOADS = [
        "/?id=1' OR '1'='1",
        "/?sql=UNION SELECT",
        "/?x=<script>alert(1)</script>",
        "/?cmd=/etc/passwd",
        "/?path=../../../etc/passwd",
    ]

    def __init__(self, client: httpx.AsyncClient):
        self.client = client

    async def detect(self, target_url: str) -> dict:
        """
        检测目标是否部署 WAF

        Returns:
            {"name": "WAF名称", "confidence": "high/medium/low", "bypass_methods": [...]}
            或 {} (未检测到 WAF)
        """
        base_url = target_url.rstrip("/")
        anomalies = []

        for payload in self.PROBE_PAYLOADS:
            try:
                response = await self.client.get(
                    f"{base_url}{payload}",
                    headers={"User-Agent": "Mozilla/5.0"},
                )

                # 检查响应头
                for header_key, waf_name in WAF_SIGNATURES["headers"].items():
                    if header_key.lower() in {k.lower() for k in response.headers}:
                        anomalies.append(("header", header_key, waf_name))

                # 检查响应体
                body_lower = response.text.lower()
                for body_key, waf_name in WAF_SIGNATURES["body"].items():
                    if body_key.lower() in body_lower:
                        anomalies.append(("body", body_key, waf_name))

                # 检查状态码
                if response.status_code in WAF_SIGNATURES["status_codes"]:
                    anomalies.append(("status", response.status_code,
                                      WAF_SIGNATURES["status_codes"][response.status_code]))

            except Exception:
                continue

        if not anomalies:
            return {}

        # 取出现次数最多的 WAF 名称
        from collections import Counter
        waf_names = [a[2] for a in anomalies if not a[2].startswith("可能")]
        if not waf_names:
            return {}

        most_common = Counter(waf_names).most_common(1)[0]
        waf_name = most_common[0]
        confidence = "high" if most_common[1] >= 2 else "medium"

        return {
            "name": waf_name,
            "confidence": confidence,
            "bypass_methods": WAF_BYPASS_STRATEGIES.get(waf_name, ["url_encode"]),
            "details": [f"{a[0]}: {a[1]}" for a in anomalies[:5]],
        }
