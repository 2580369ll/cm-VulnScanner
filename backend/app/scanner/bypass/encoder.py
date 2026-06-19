"""Payload 编码器 — 对 Payload 进行各种编码变换以绕过 WAF"""

import random
from urllib.parse import quote


def url_encode(payload: str) -> str:
    """URL 编码"""
    return quote(payload, safe="")


def double_url_encode(payload: str) -> str:
    """双重 URL 编码"""
    return quote(quote(payload, safe=""), safe="")


def hex_encode(payload: str) -> str:
    """十六进制编码"""
    return "0x" + payload.encode().hex()


def unicode_encode(payload: str) -> str:
    """Unicode 编码 (\uXXXX 格式)"""
    result = []
    for char in payload:
        result.append(f"\\u{ord(char):04x}")
    return "".join(result)


def html_entity_encode(payload: str) -> str:
    """HTML 实体编码"""
    result = []
    for char in payload:
        result.append(f"&#{ord(char)};")
    return "".join(result)


def case_randomize(payload: str) -> str:
    """随机大小写混淆"""
    result = []
    for char in payload:
        if char.isalpha():
            if random.choice([True, False]):
                result.append(char.upper())
            else:
                result.append(char.lower())
        else:
            result.append(char)
    return "".join(result)


def space_variant(payload: str, variant: str = "comment") -> str:
    """空格替换变体

    Args:
        payload: 原始 Payload
        variant: comment / tab / newline / mysql9
    """
    variants = {
        "comment": "/**/",
        "tab": "%09",
        "newline": "%0a",
        "mysql9": "%09",
    }
    replacement = variants.get(variant, "/**/")
    return payload.replace(" ", replacement)


# 编码器注册表
ENCODERS = {
    "url_encode": url_encode,
    "double_url_encode": double_url_encode,
    "hex_encode": hex_encode,
    "unicode_encode": unicode_encode,
    "html_entity_encode": html_entity_encode,
    "case_randomize": case_randomize,
}


def apply_encoder(payload: str, encoder_name: str) -> str:
    """应用指定编码器"""
    encoder = ENCODERS.get(encoder_name)
    if encoder:
        return encoder(payload)
    return payload


def apply_encoders(payload: str, encoder_names: list[str]) -> str:
    """依次应用多个编码器"""
    result = payload
    for name in encoder_names:
        result = apply_encoder(result, name)
    return result
