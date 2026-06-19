"""Tamper 脚本 — 对 SQL 注入 Payload 进行语义级变换以绕过 WAF

类 sqlmap tamper 脚本设计
"""


def space2comment(payload: str) -> str:
    """空格替换为 /**/"""
    return payload.replace(" ", "/**/")


def space2mysql9(payload: str) -> str:
    """空格替换为 %09 (MySQL 视为空白)"""
    return payload.replace(" ", "%09")


def between(payload: str) -> str:
    """> 替换为 NOT BETWEEN 0 AND"""
    return payload.replace(">", " NOT BETWEEN 0 AND ")


def equaltolike(payload: str) -> str:
    """= 替换为 LIKE"""
    return payload.replace("=", " LIKE ")


def apostrophemask(payload: str) -> str:
    """单引号替换为 UTF-8 全角形式 (%EF%BC%87)"""
    return payload.replace("'", "%EF%BC%87")


def chardoubleencode(payload: str) -> str:
    """双重 URL 编码"""
    from urllib.parse import quote
    return quote(quote(payload, safe=""), safe="")


def percentage(payload: str) -> str:
    """在每个字符前添加 %"""
    return "".join(f"%{ord(c):02x}" for c in payload)


def random_case(payload: str) -> str:
    """随机大小写 (仅对 SQL 关键字)"""
    import re
    def randomize(match):
        word = match.group(0)
        import random
        return "".join(
            c.upper() if random.choice([True, False]) else c.lower()
            for c in word
        )

    keywords = r'\b(SELECT|UNION|FROM|WHERE|AND|OR|INSERT|UPDATE|DELETE|DROP|TABLE|NULL|SLEEP|BENCHMARK|WAITFOR|DELAY)\b'
    return re.sub(keywords, randomize, payload, flags=re.IGNORECASE)


def concat2concatws(payload: str) -> str:
    """CONCAT() 替换为 CONCAT_WS()"""
    return payload.replace("CONCAT(", "CONCAT_WS(CHAR(32),")


# Tamper 注册表
TAMPERS = {
    "space2comment": space2comment,
    "space2mysql9": space2mysql9,
    "between": between,
    "equaltolike": equaltolike,
    "apostrophemask": apostrophemask,
    "chardoubleencode": chardoubleencode,
    "percentage": percentage,
    "random_case": random_case,
    "concat2concatws": concat2concatws,
}


def apply_tamper(payload: str, tamper_name: str) -> str:
    """应用指定 Tamper 脚本"""
    tamper_func = TAMPERS.get(tamper_name)
    if tamper_func:
        return tamper_func(payload)
    return payload


def apply_tampers(payload: str, tamper_names: list[str]) -> str:
    """依次应用多个 Tamper 脚本"""
    result = payload
    for name in tamper_names:
        result = apply_tamper(result, name)
    return result
