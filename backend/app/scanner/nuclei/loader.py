"""Nuclei YAML 模板加载器

解析 Nuclei 格式的 YAML 模板文件，提取:
- id, name, severity, description, tags
- requests (method, path, headers, body)
- matchers (type: word/status/regex, condition: and/or, words/status/regex)

支持 {{BaseURL}} 变量语法。
"""

import os
import re
import yaml
from pathlib import Path
from dataclasses import dataclass, field


@dataclass
class NucleiMatcher:
    """Nuclei 模板的匹配器"""
    type: str = "word"       # word / status / regex
    condition: str = "or"    # and / or
    words: list[str] = field(default_factory=list)
    status: list[int] = field(default_factory=list)
    regex: list[str] = field(default_factory=list)
    part: str = "body"       # body / header
    negative: bool = False


@dataclass
class NucleiRequest:
    """Nuclei 模板中的 HTTP 请求定义"""
    method: str = "GET"
    path: str = "/"
    headers: dict = field(default_factory=dict)
    body: str = ""


@dataclass
class NucleiTemplate:
    """Nuclei 模板"""
    id: str = ""
    name: str = ""
    severity: str = "medium"  # critical/high/medium/low/info
    description: str = ""
    tags: list[str] = field(default_factory=list)
    author: str = ""
    requests: list[NucleiRequest] = field(default_factory=list)
    matchers: list[NucleiMatcher] = field(default_factory=list)
    matchers_condition: str = "or"  # and/or


def load_template(filepath: str) -> NucleiTemplate | None:
    """从文件加载单个 Nuclei 模板"""
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        if not data or "id" not in data:
            return None

        info = data.get("info", {})

        # 解析 matchers
        matchers = []
        for m in data.get("matchers", []):
            matchers.append(NucleiMatcher(
                type=m.get("type", "word"),
                condition=m.get("condition", "or"),
                words=m.get("words", []),
                status=m.get("status", []),
                regex=m.get("regex", []),
                part=m.get("part", "body"),
                negative=m.get("negative", False),
            ))

        # 解析 HTTP requests
        requests_raw = data.get("requests", [])
        if isinstance(requests_raw, dict):
            requests_raw = [requests_raw]

        http_requests = []
        for req_block in requests_raw:
            # 处理 raw HTTP 格式
            raw = req_block.get("raw", [])
            if isinstance(raw, str):
                raw = [raw]

            for raw_req in raw:
                parsed = _parse_raw_http(raw_req)
                if parsed:
                    http_requests.append(parsed)

            # 处理结构化格式
            if not raw:
                method = req_block.get("method", "GET")
                path = req_block.get("path", "/")
                http_requests.append(NucleiRequest(
                    method=method.upper(),
                    path=str(path),
                    headers=req_block.get("headers", {}),
                    body=req_block.get("body", ""),
                ))

        return NucleiTemplate(
            id=data["id"],
            name=info.get("name", data["id"]),
            severity=info.get("severity", "medium"),
            description=info.get("description", ""),
            tags=data.get("tags", []),
            author=info.get("author", ""),
            requests=http_requests,
            matchers=matchers,
            matchers_condition=data.get("matchers-condition", "or"),
        )
    except Exception:
        return None


def load_templates_from_dir(directory: str) -> list[NucleiTemplate]:
    """从目录加载所有 YAML 模板"""
    templates = []
    path = Path(directory)
    if not path.exists():
        return templates

    for yaml_file in path.rglob("*.yaml"):
        t = load_template(str(yaml_file))
        if t:
            templates.append(t)

    for yaml_file in path.rglob("*.yml"):
        t = load_template(str(yaml_file))
        if t:
            templates.append(t)

    return templates


def _parse_raw_http(raw: str) -> NucleiRequest | None:
    """解析 Nuclei raw HTTP 格式"""
    lines = raw.strip().split("\n")
    if not lines:
        return None

    # 第一行: METHOD /path HTTP/1.1
    first = lines[0].strip()
    parts = first.split(" ")
    if len(parts) < 2:
        return None

    method = parts[0]
    path = parts[1]

    headers = {}
    body_start = 0
    for i, line in enumerate(lines[1:], 1):
        line = line.strip()
        if not line:
            body_start = i + 1
            break
        if ":" in line:
            key, val = line.split(":", 1)
            headers[key.strip()] = val.strip()

    body = "\n".join(lines[body_start:]).strip() if body_start > 0 else ""

    return NucleiRequest(method=method, path=path, headers=headers, body=body)


VARIABLE_RE = re.compile(r"\{\{(\w+)\}\}")


def substitute_variables(template_str: str, variables: dict) -> str:
    """替换 {{变量}} 语法"""
    def replace(match):
        key = match.group(1)
        return str(variables.get(key, match.group(0)))
    return VARIABLE_RE.sub(replace, template_str)
