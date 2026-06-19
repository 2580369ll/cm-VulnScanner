<?php
/**
 * SQL 注入漏洞靶场
 *
 * 包含三种注入点：
 * 1. GET 参数注入 (search)
 * 2. POST 登录绕过 (username/password)
 * 3. 数字型注入 (id)
 */

// 模拟数据库连接
$fake_db = [
    ['id' => 1, 'name' => '张三', 'email' => 'zhangsan@example.com'],
    ['id' => 2, 'name' => '李四', 'email' => 'lisi@example.com'],
    ['id' => 3, 'name' => '王五', 'email' => 'wangwu@example.com'],
    ['admin' => ['username' => 'admin', 'password' => 'admin123!@#']],
];

$message = '';
$results = [];

// ====== 1. GET 参数注入 (search) ======
if (isset($_GET['search'])) {
    $search = $_GET['search'];
    // 漏洞：直接拼接用户输入到 SQL 语句
    $sql = "SELECT * FROM users WHERE name LIKE '%" . $search . "%'";

    // 模拟执行 SQL 并捕获"错误"
    if (strpos($search, "'") !== false || strpos($search, '"') !== false) {
        $message = '<div style="color:red;background:#fff0f0;padding:10px;border:1px solid red;border-radius:5px;">
            <strong>⚠️ MySQL Error:</strong> You have an error in your SQL syntax;
            check the manual that corresponds to your MySQL server version for the right syntax
            to use near \'' . htmlspecialchars($search) . '\' at line 1
        </div>';
    }

    // 正常搜索
    foreach ($fake_db as $user) {
        if (isset($user['name']) && stripos($user['name'], str_replace(["'", '"', '%', '_'], '', $search)) !== false) {
            $results[] = $user;
        }
    }
}

// ====== 2. POST 登录绕过 ======
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['username'], $_POST['password'])) {
    $username = $_POST['username'];
    $password = $_POST['password'];

    // 漏洞：SQL 拼接认证
    $sql = "SELECT * FROM users WHERE username='" . $username . "' AND password='" . $password . "'";

    // 检测 SQL 注入关键词
    $sqli_patterns = ["' OR", "' or", "1=1", "1'='1", "' --", "'--", "' #", "'#", "UNION", "union"];
    $is_injection = false;
    foreach ($sqli_patterns as $pattern) {
        if (strpos($username . $password, $pattern) !== false) {
            $is_injection = true;
            break;
        }
    }

    if ($is_injection) {
        $message = '<div style="color:green;background:#f0fff0;padding:15px;border:2px solid green;border-radius:5px;font-size:18px;">
            <strong>✅ 登录成功！(SQL 注入绕过认证)</strong><br>
            <small>执行的 SQL: <code>' . htmlspecialchars($sql) . '</code></small><br>
            <small>欢迎回来，管理员！Flag: flag{sqli_b00l3an_byp4ss_succ3ss}</small>
        </div>';
    } elseif ($username === 'admin' && $password === 'admin123!@#') {
        $message = '<div style="color:green;background:#f0fff0;padding:15px;border-radius:5px;">
            <strong>✅ 正常登录成功</strong><br>
            <small>欢迎, admin</small>
        </div>';
    } else {
        $message = '<div style="color:red;background:#fff0f0;padding:10px;border-radius:5px;">
            <strong>❌ 登录失败</strong> — 用户名或密码错误
        </div>';
    }
}

// ====== 3. 数字型注入 (id) ======
if (isset($_GET['id'])) {
    $id = $_GET['id'];
    // 漏洞：数字型 SQL 注入
    $sql = "SELECT * FROM users WHERE id = " . $id;

    $found = null;
    foreach ($fake_db as $user) {
        if (isset($user['id']) && $user['id'] == intval($id)) {
            $found = $user;
            break;
        }
    }

    if ($found) {
        $results = [$found];
    } elseif (!is_numeric($id)) {
        // 模拟 SQL 错误
        if (preg_match("/UNION|union|SLEEP|sleep|BENCHMARK/i", $id)) {
            if (preg_match("/SLEEP|sleep/i", $id)) {
                sleep(3); // 模拟时间延迟
            }
            $message = '<div style="color:orange;background:#fffff0;padding:10px;border:1px solid orange;border-radius:5px;">
                <strong>🔍 检测到注入尝试</strong><br>
                <small>SQL: <code>' . htmlspecialchars($sql) . '</code></small>
            </div>';
        }
    }
}
?>
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <title>SQL 注入靶场 — VulnScanner Test</title>
    <style>
        * { box-sizing: border-box; }
        body { font-family: -apple-system, sans-serif; max-width: 800px; margin: 40px auto; padding: 20px; background: #1a1a2e; color: #eee; }
        h1 { color: #e94560; }
        .card { background: #16213e; padding: 20px; margin: 20px 0; border-radius: 8px; border: 1px solid #0f3460; }
        .card h2 { margin-top: 0; color: #53a8b6; }
        input, button { padding: 10px; border-radius: 4px; border: 1px solid #0f3460; background: #1a1a2e; color: #eee; width: 100%; margin: 5px 0; }
        button { background: #e94560; cursor: pointer; border: none; font-weight: bold; }
        button:hover { background: #c23152; }
        table { width: 100%; border-collapse: collapse; margin-top: 10px; }
        th, td { padding: 10px; text-align: left; border-bottom: 1px solid #0f3460; }
        a { color: #53a8b6; }
    </style>
</head>
<body>
    <h1>🧪 SQL 注入漏洞靶场</h1>
    <p>此靶场用于测试 VulnScanner 的 SQL 注入检测能力</p>

    <?= $message ?>

    <!-- 注入点1: GET 搜索 -->
    <div class="card">
        <h2>注入点 1: GET 参数 search (Error-based)</h2>
        <form method="GET">
            <input type="text" name="search" placeholder="搜索用户 (例如: 张)" value="<?= htmlspecialchars($_GET['search'] ?? '') ?>">
            <button type="submit">搜索</button>
        </form>
        <?php if ($results && isset($_GET['search'])): ?>
        <table>
            <tr><th>ID</th><th>姓名</th><th>邮箱</th></tr>
            <?php foreach ($results as $user): ?>
            <tr><td><?= $user['id'] ?? '-' ?></td><td><?= htmlspecialchars($user['name'] ?? '') ?></td><td><?= htmlspecialchars($user['email'] ?? '') ?></td></tr>
            <?php endforeach; ?>
        </table>
        <?php endif; ?>
    </div>

    <!-- 注入点2: POST 登录绕过 -->
    <div class="card">
        <h2>注入点 2: POST 登录 (Boolean-based Blind)</h2>
        <form method="POST">
            <input type="text" name="username" placeholder="用户名">
            <input type="password" name="password" placeholder="密码">
            <button type="submit">登录</button>
        </form>
    </div>

    <!-- 注入点3: GET 数字型 -->
    <div class="card">
        <h2>注入点 3: GET 数字型 id (Time-based / Union)</h2>
        <p>试试: <a href="?id=1">?id=1</a> | <a href="?id=2">?id=2</a> | <a href="?id=3">?id=3</a></p>
        <?php if (isset($_GET['id']) && $results): ?>
        <table>
            <tr><th>ID</th><th>姓名</th><th>邮箱</th></tr>
            <?php foreach ($results as $user): ?>
            <tr><td><?= $user['id'] ?? '-' ?></td><td><?= htmlspecialchars($user['name'] ?? '') ?></td><td><?= htmlspecialchars($user['email'] ?? '') ?></td></tr>
            <?php endforeach; ?>
        </table>
        <?php endif; ?>
    </div>
</body>
</html>
