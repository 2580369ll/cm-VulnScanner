"""CSRF 跨站请求伪造检测插件"""

from bs4 import BeautifulSoup

from app.scanner.plugins.base import BasePlugin, InjectionPoint, Finding


class CSRFPlugin(BasePlugin):
    """CSRF 检测插件"""

    name = "csrf"
    vuln_type = "csrf"

    async def check(self, ip: InjectionPoint) -> list[Finding]:
        findings = []

        # 只检查 POST 表单
        if ip.method != "POST" or not ip.form_action:
            return findings

        try:
            resp = await self.client.get(ip.url)

            # 1) 检查表单中是否缺少 CSRF token
            soup = BeautifulSoup(resp.text, "lxml")
            forms = soup.find_all("form", method=lambda m: m and m.upper() == "POST")

            for form in forms:
                if not self._has_csrf_token(form):
                    findings.append(Finding(
                        vuln_type="csrf",
                        severity="medium",
                        confidence=0.75,
                        endpoint=ip.url,
                        parameter="(form)",
                        method="POST",
                        payload="missing_csrf_token",
                        payload_variant="direct",
                        response_evidence=f"表单 action={form.get('action','')} 缺少 CSRF Token",
                        poc=f"POST {ip.url} — 表单未包含防CSRF字段",
                        description="CSRF: POST 表单缺少 CSRF Token 防护",
                        remediation="为所有状态变更的表单添加 CSRF Token",
                    ))

            # 2) 检查 Cookie 的 SameSite 属性
            set_cookie = resp.headers.get("set-cookie", "")
            if set_cookie and "samesite" not in set_cookie.lower():
                findings.append(Finding(
                    vuln_type="csrf",
                    severity="low",
                    confidence=0.60,
                    endpoint=ip.url,
                    parameter="(cookie)",
                    method="GET",
                    payload="missing_samesite",
                    payload_variant="direct",
                    response_evidence=f"Cookie 缺少 SameSite 属性",
                    poc=f"Set-Cookie: {set_cookie[:100]}",
                    description="CSRF: Session Cookie 缺少 SameSite 属性",
                    remediation="为 Session Cookie 设置 SameSite=Lax 或 Strict",
                ))

            # 3) 检查是否缺少 CORS/Origin 校验头
            test_resp = await self.client.post(
                ip.form_action or ip.url,
                data={ip.param_name: "test"},
                headers={"Origin": "https://evil.com", "Referer": "https://evil.com/fake"},
            )
            if test_resp.status_code == 200:
                findings.append(Finding(
                    vuln_type="csrf",
                    severity="medium",
                    confidence=0.70,
                    endpoint=ip.url,
                    parameter="(origin)",
                    method="POST",
                    payload="cross_origin_accepted",
                    payload_variant="direct",
                    response_evidence=f"跨域 POST 请求被接受 (Origin: evil.com → 200)",
                    poc=f"curl -X POST '{ip.url}' -H 'Origin: https://evil.com' -d '{ip.param_name}=test'",
                    description="CSRF: 跨域请求未被拦截，缺少 Origin/Referer 校验",
                    remediation="验证 Origin/Referer 请求头，拒绝跨域 POST",
                ))

        except Exception:
            pass

        return findings

    def _has_csrf_token(self, form) -> bool:
        """检查表单是否包含 CSRF token"""
        csrf_names = ["csrf", "csrf_token", "_csrf", "_token", "authenticity_token",
                       "xsrf", "__RequestVerificationToken", "nonce"]
        for inp in form.find_all("input"):
            name = (inp.get("name") or "").lower()
            if any(csrf in name for csrf in csrf_names):
                return True
            if inp.get("type") == "hidden" and any(csrf in name for csrf in csrf_names):
                return True
        return False
