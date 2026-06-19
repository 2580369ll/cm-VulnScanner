"""WAF 绕过模块 — 统一入口

自动判断 bypass method 属于 encoder 还是 tamper 注册表，
支持链式绕过：tamper → encoder 顺序应用。
"""

from app.scanner.bypass.encoder import ENCODERS, apply_encoder, space_variant
from app.scanner.bypass.tamper import TAMPERS, apply_tamper


def apply_bypass(payload: str, method_name: str) -> str:
    """统一的绕过入口：自动判断 method_name 类型并应用

    Args:
        payload: 原始 Payload
        method_name: 绕过方法名（encoder 或 tamper ID）

    Returns:
        变换后的 Payload（如果方法不存在则返回原值）
    """
    # 先查 tamper 注册表（语义变换）
    if method_name in TAMPERS:
        return apply_tamper(payload, method_name)

    # 再查 encoder 注册表（编码变换）
    if method_name in ENCODERS:
        return apply_encoder(payload, method_name)

    # 空格变体特殊处理
    if method_name in ("space2comment", "space2mysql9", "space2tab", "space2newline"):
        variant_map = {
            "space2comment": "comment",
            "space2mysql9": "mysql9",
            "space2tab": "tab",
            "space2newline": "newline",
        }
        return space_variant(payload, variant_map.get(method_name, "comment"))

    # 大小写混淆
    if method_name == "size_mix":
        return apply_encoder(payload, "case_randomize")

    return payload


def apply_bypass_chain(payload: str, method_names: list[str]) -> str:
    """依次应用多个绕过方法

    Args:
        payload: 原始 Payload
        method_names: 绕过方法名列表（按顺序应用）

    Returns:
        变换后的 Payload
    """
    result = payload
    for name in method_names:
        result = apply_bypass(result, name)
    return result
