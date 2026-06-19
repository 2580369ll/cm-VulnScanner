"""文件上传漏洞检测插件

检测方法:
1. 发现上传表单（<input type="file">）
2. 依次上传各类恶意文件
3. 验证上传结果 — 检测文件是否可访问/解析为代码
"""

import io
from urllib.parse import urljoin

from app.scanner.plugins.base import BasePlugin, InjectionPoint, Finding
from app.scanner.payloads.upload_payloads import get_upload_payloads


class FileUploadPlugin(BasePlugin):
    """文件上传漏洞检测插件"""

    name = "file_upload"
    vuln_type = "file_upload"

    async def check(self, ip: InjectionPoint) -> list[Finding]:
        findings = []

        # 只处理文件上传类型的注入点
        if ip.param_type != "file":
            return findings

        upload_payloads = get_upload_payloads()

        for upload in upload_payloads[:8]:  # 限制探测数量
            finding = await self._test_upload(ip, upload)
            if finding:
                findings.append(finding)
                # 找到一个成功的就不继续了
                break

        return findings

    async def _test_upload(self, ip: InjectionPoint, upload: dict) -> Finding | None:
        """测试单个上传 Payload"""
        try:
            # 构建上传请求
            files = {
                ip.param_name: (
                    upload["filename"],
                    io.BytesIO(upload["content"]),
                    upload["content_type"],
                )
            }

            # 如果有其他表单字段，一并发送
            data = {}
            if ip.form_inputs:
                for inp in ip.form_inputs:
                    if inp["name"] != ip.param_name and inp["type"] != "file":
                        data[inp["name"]] = "test"

            resp = await self.client.post(
                ip.form_action or ip.url,
                data=data,
                files=files,
            )

            # 1) 检查响应中是否包含文件路径
            file_url = self._extract_file_url(resp.text, upload["filename"])

            if file_url:
                # 2) 尝试访问上传的文件
                full_url = urljoin(ip.form_action or ip.url, file_url)
                try:
                    file_resp = await self.client.get(full_url)
                except Exception:
                    return None

                # 3) 检查文件是否被解析为 PHP（关键验证）
                is_executed = self._check_execution(file_resp.text, upload)

                severity = "critical" if is_executed else "medium"

                return Finding(
                    vuln_type="file_upload",
                    severity=severity,
                    endpoint=ip.form_action or ip.url,
                    parameter=ip.param_name,
                    method="POST",
                    payload=upload["description"],
                    payload_variant=upload["bypass_type"],
                    request_raw=f"POST {ip.form_action or ip.url}\nFile: {upload['filename']}\nContent-Type: {upload['content_type']}",
                    response_raw=self.format_response(resp),
                    response_evidence=f"文件上传成功，路径: {file_url}\n{'PHP代码已执行！' if is_executed else '文件可访问但未解析为PHP'}",
                    poc=f"上传文件 {upload['filename']} → 访问 {full_url}",
                    description=self._build_description(upload, is_executed),
                    remediation=self._build_remediation(upload),
                )

            # 没提取到文件路径，可能上传失败或有保护
            return None

        except Exception:
            return None

    def _extract_file_url(self, text: str, filename: str) -> str | None:
        """从响应中提取上传后的文件 URL"""
        import re

        # 常见模式
        patterns = [
            rf'(?:src|href|path|url|location)\s*[=:]\s*["\']([^"\']*{re.escape(filename)}[^"\']*)["\']',
            rf'["\'](/?uploads?/[^"\']*{re.escape(filename)}[^"\']*)["\']',
            rf'["\'](/?files?/[^"\']*{re.escape(filename)}[^"\']*)["\']',
            rf'["\'](/?images?/[^"\']*{re.escape(filename)}[^"\']*)["\']',
            rf'["\'](/[^"\']*{re.escape(filename)})["\']',
        ]

        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return match.group(1)

        # 简单匹配：包含文件名的路径
        if filename in text:
            simple_match = re.search(rf'(/[^\s"\']*{re.escape(filename)})', text)
            if simple_match:
                return simple_match.group(1)

        return None

    def _check_execution(self, response_text: str, upload: dict) -> bool:
        """检查 PHP 代码是否被执行"""
        # phpinfo() 执行标志
        phpinfo_indicators = [
            "PHP Version",
            "phpinfo()",
            "PHP Extension",
            "PHP License",
            "Configuration File (php.ini)",
            "Loaded Configuration File",
            "PHP Version =>",
        ]

        # system() 执行标志（如果有）
        system_indicators = [
            "uid=",  # Linux whoami 输出
            "nt authority\\system",  # Windows
        ]

        for indicator in phpinfo_indicators + system_indicators:
            if indicator.lower() in response_text.lower():
                return True

        return False

    def _build_description(self, upload: dict, is_executed: bool) -> str:
        """构建漏洞描述"""
        bypass_desc = {
            "none": "无任何过滤",
            "extension": "扩展名黑名单绕过",
            "extension_case": "大小写混淆绕过",
            "extension_dot": "尾部加点绕过",
            "content_type": "Content-Type 校验绕过",
            "magic_bytes_gif": "GIF 魔法字节 + 文件内容校验绕过",
            "magic_bytes_png": "PNG 魔法字节 + 文件内容校验绕过",
            "magic_bytes_jpg": "JPEG 魔法字节 + 文件内容校验绕过",
            "double_extension": "双扩展名绕过（Apache 解析漏洞）",
            "double_extension_semicolon": "分号截断绕过",
            "htaccess": ".htaccess 覆盖解析规则",
        }

        bypass = bypass_desc.get(upload["bypass_type"], upload["bypass_type"])
        exec_status = "PHP 代码已成功执行" if is_executed else "文件已上传但未被解析为 PHP"

        return f"文件上传漏洞（{bypass}）：上传 `{upload['filename']}` 成功。{exec_status}。"

    def _build_remediation(self, upload: dict) -> str:
        """构建修复建议"""
        return (
            "1. 使用白名单限制允许的文件扩展名\n"
            "2. 验证文件 Content-Type 与魔数是否一致\n"
            "3. 将上传目录设置为不可执行脚本\n"
            "4. 对上传文件重命名（使用 UUID）\n"
            "5. 限制上传目录的访问权限"
        )
