"""Nuclei 模板执行器

对单个端点执行 Nuclei 模板，检查匹配器，生成 Finding。
"""

import re

import httpx

from app.scanner.nuclei.loader import (
    NucleiTemplate, NucleiRequest, NucleiMatcher,
    substitute_variables,
)
from app.scanner.plugins.base import Finding


async def execute_template(
    client: httpx.AsyncClient,
    template: NucleiTemplate,
    base_url: str,
) -> list[NucleiMatcher]:
    """对目标执行模板，返回匹配成功的 matcher 列表"""
    matched = []

    for req in template.requests:
        url = _build_url(base_url, req.path)
        try:
            resp = await client.request(
                method=req.method,
                url=url,
                headers=req.headers or None,
                content=req.body or None,
            )

            for matcher in template.matchers:
                if _check_matcher(resp, matcher):
                    matched.append(matcher)
        except Exception:
            continue

    return matched


async def template_to_finding(
    client: httpx.AsyncClient,
    template: NucleiTemplate,
    url: str,
    param_name: str = "",
) -> Finding | None:
    """执行模板并转换为 Finding"""
    matchers = await execute_template(client, template, url)

    if not matchers:
        return None

    # 取第一个匹配的 matcher 作为证据
    m = matchers[0]
    evidence = f"[Nuclei] {template.id}: "
    if m.type == "word":
        evidence += f"匹配关键词: {m.words}"
    elif m.type == "status":
        evidence += f"匹配状态码: {m.status}"
    elif m.type == "regex":
        evidence += f"匹配正则: {m.regex}"

    # 映射 Nuclei severity
    sev_map = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "info": "info"}
    severity = sev_map.get(template.severity, "medium")

    return Finding(
        vuln_type="nuclei",
        severity=severity,
        confidence=0.90 if len(matchers) >= 2 else 0.80,
        endpoint=url,
        parameter=param_name,
        method=template.requests[0].method if template.requests else "GET",
        payload=template.id,
        payload_variant="nuclei_template",
        response_evidence=evidence,
        poc=f"nuclei -t {template.id} -u {url}",
        description=f"[{template.id}] {template.name}: {template.description}",
        remediation="根据具体漏洞类型采取相应修复措施",
    )


def _build_url(base: str, path: str) -> str:
    base = base.rstrip("/")
    path = substitute_variables(path, {"BaseURL": base})
    # 如果替换后已经是完整 URL，直接返回
    if path.startswith("http://") or path.startswith("https://"):
        return path
    if not path.startswith("/"):
        path = "/" + path
    return base + path


def _check_matcher(response, matcher: NucleiMatcher) -> bool:
    """检查响应是否满足单个 matcher 条件"""
    result = False

    # 选择检查目标
    content = response.text
    if matcher.part == "header":
        content = "\n".join(f"{k}: {v}" for k, v in response.headers.items())

    # 按类型检查
    if matcher.type == "word":
        if matcher.condition == "and":
            result = all(w.lower() in content.lower() for w in matcher.words)
        else:
            result = any(w.lower() in content.lower() for w in matcher.words) if matcher.words else True

    elif matcher.type == "status":
        result = response.status_code in matcher.status

    elif matcher.type == "regex":
        if matcher.condition == "and":
            result = all(re.search(r, content, re.IGNORECASE) for r in matcher.regex)
        else:
            result = any(re.search(r, content, re.IGNORECASE) for r in matcher.regex) if matcher.regex else True

    # 支持 negative 反向匹配
    if matcher.negative:
        result = not result

    return result
