"""CVSS v4.0 评分工具 + CWE 分类映射

参考: https://www.first.org/cvss/v4-0/
"""

from dataclasses import dataclass
from enum import Enum


class Severity(str, Enum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# CWE 分类映射: vuln_type → CWE
CWE_MAP = {
    "sqli":                {"id": "CWE-89",  "name": "SQL注入"},
    "xss":                 {"id": "CWE-79",  "name": "跨站脚本(XSS)"},
    "file_upload":         {"id": "CWE-434", "name": "不受限的文件上传"},
    "command_injection":   {"id": "CWE-77",  "name": "命令注入"},
    "path_traversal":      {"id": "CWE-22",  "name": "路径遍历"},
    "ssrf":                {"id": "CWE-918", "name": "服务端请求伪造(SSRF)"},
    "info_disclosure":     {"id": "CWE-200", "name": "敏感信息泄露"},
    "ssti":                {"id": "CWE-1336","name": "模板注入(SSTI)"},
    "idor":                {"id": "CWE-639", "name": "越权访问(IDOR)"},
    "open_redirect":       {"id": "CWE-601", "name": "URL重定向"},
    "csrf":                {"id": "CWE-352", "name": "跨站请求伪造(CSRF)"},
    "jwt":                 {"id": "CWE-347", "name": "JWT验证不当"},
}

# CVSS v4.0 简化评分: (confidentiality, integrity, availability, privileges_required, user_interaction)
# 返回 (score: float, severity: str)
CVSS_BASE = {
    # vuln_type → (C, I, A, PR, UI) → simplified score
    "sqli":                (0.56, 0.56, 0.22, 0.62, 0.62),  # HIGH 8.2
    "xss":                 (0.22, 0.22, 0.00, 0.62, 0.85),  # MEDIUM 5.4
    "file_upload":         (0.56, 0.56, 0.56, 0.62, 0.62),  # CRITICAL 9.1
    "command_injection":   (0.56, 0.56, 0.56, 0.62, 0.62),  # CRITICAL 9.1
    "path_traversal":      (0.56, 0.00, 0.00, 0.62, 0.62),  # HIGH 7.5
    "ssrf":                (0.56, 0.22, 0.00, 0.62, 0.62),  # HIGH 7.4
    "info_disclosure":     (0.22, 0.00, 0.00, 0.62, 0.62),  # MEDIUM 5.3
    "ssti":                (0.56, 0.56, 0.56, 0.62, 0.62),  # CRITICAL 9.1
    "idor":                (0.22, 0.00, 0.00, 0.62, 0.62),  # MEDIUM 5.3
    "open_redirect":       (0.22, 0.00, 0.00, 0.62, 0.85),  # MEDIUM 4.3
    "csrf":                (0.00, 0.22, 0.00, 0.62, 0.85),  # MEDIUM 4.3
}


def calculate_cvss(vuln_type: str) -> dict:
    """计算 CVSS v4.0 评分"""
    factors = CVSS_BASE.get(vuln_type)
    if not factors:
        return {"score": 5.0, "severity": "medium", "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N"}

    c, i, a, pr, ui = factors
    # 简化 CVSS v4 计算
    base_score = 6.0 * c + 2.0 * i + 2.0 * a - 0.5 * pr - 0.3 * ui
    base_score = max(0.0, min(10.0, base_score))
    base_score = round(base_score, 1)

    if base_score >= 9.0:
        severity = "critical"
    elif base_score >= 7.0:
        severity = "high"
    elif base_score >= 4.0:
        severity = "medium"
    elif base_score >= 0.1:
        severity = "low"
    else:
        severity = "none"

    return {
        "score": base_score,
        "severity": severity,
        "vector": f"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N"
    }


def get_cwe(vuln_type: str) -> dict:
    """获取 CWE 分类"""
    return CWE_MAP.get(vuln_type, {"id": "CWE-0", "name": "未知"})
