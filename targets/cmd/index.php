<?php
/**
 * 命令注入漏洞靶场
 *
 * 包含两个注入点：
 * 1. GET 参数 cmd — 直接传入 shell_exec()，无任何过滤
 * 2. POST 参数 host — 拼接到 ping 命令中执行
 *
 * 安全模式: ?safe=1 (GET) 启用 escapeshellcmd() 过滤，用于对比测试
 */

$output = '';
$cmd = $_GET['cmd'] ?? '';
$host = $_POST['host'] ?? '';
$safe = isset($_GET['safe']) && $_GET['safe'] == '1';

// ====== 注入点 1: GET cmd 参数 ======
if ($cmd) {
    if ($safe) {
        // 安全模式: 使用 escapeshellcmd() 过滤
        $filtered_cmd = escapeshellcmd($cmd);
        $output = shell_exec($filtered_cmd);
    } else {
        // 漏洞: 直接执行用户输入的命令
        $output = shell_exec($cmd);
    }
}

// ====== 注入点 2: POST host 参数 (Ping 命令拼接) ======
if ($host && $_SERVER['REQUEST_METHOD'] === 'POST' && !$cmd) {
    // 检测操作系统选择 ping 参数
    $ping_cmd = (PHP_OS_FAMILY === 'Windows' || strtoupper(substr(PHP_OS, 0, 3)) === 'WIN')
        ? "ping -n 2 "
        : "ping -c 2 ";

    // 漏洞: host 参数直接拼接到命令中
    $output = shell_exec($ping_cmd . $host);

    // 如果没有输出，可能是 Windows ping 被快速执行
    if ($output === null || trim($output) === '') {
        $output = "[无输出 — 命令可能执行失败或返回为空]";
    }
}

// 检测输出中的注入成功标志
$is_potential_injection = false;
$injection_indicators = [
    'uid=', 'gid=', 'groups=',
    'nt authority', 'administrator',
    'root:', 'daemon:', 'bin:',
    'www-data',
    '/bin/bash', '/bin/sh',
    'Microsoft Windows',
    'Windows IP Configuration',
    'command not found',
    'not recognized',
];
foreach ($injection_indicators as $indicator) {
    if ($output && stripos($output, $indicator) !== false) {
        $is_potential_injection = true;
        break;
    }
}
?>
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <title>命令注入靶场 — VulnScanner Test</title>
    <style>
        * { box-sizing: border-box; }
        body { font-family: -apple-system, sans-serif; max-width: 900px; margin: 40px auto; padding: 20px; background: #1a1a2e; color: #eee; }
        h1 { color: #e94560; }
        .card { background: #16213e; padding: 20px; margin: 20px 0; border-radius: 8px; border: 1px solid #0f3460; }
        .card h2 { margin-top: 0; color: #53a8b6; }
        input, button { padding: 10px; border-radius: 4px; border: 1px solid #0f3460; background: #1a1a2e; color: #eee; width: 100%; margin: 5px 0; }
        button { background: #e94560; cursor: pointer; border: none; font-weight: bold; }
        button:hover { background: #c23152; }
        pre { background: #0a0a1a; padding: 15px; border-radius: 4px; overflow-x: auto; white-space: pre-wrap; color: #0f0; }
        .injection-warning { background: #332200; border: 2px solid #ff9900; color: #ffcc00; padding: 10px; border-radius: 4px; margin: 10px 0; }
        .safe-mode { background: #003300; border: 1px solid #00cc00; color: #99ff99; padding: 8px; border-radius: 4px; margin: 10px 0; }
        label.checkbox { display: flex; align-items: center; gap: 8px; width: auto; }
        label.checkbox input { width: auto; }
        code { color: #53a8b6; background: #0a0a1a; padding: 2px 6px; border-radius: 3px; }
        .test-links { margin: 10px 0; }
        .test-links a { display: inline-block; color: #53a8b6; margin-right: 15px; }
    </style>
</head>
<body>
    <h1>&#x1f9ea; 命令注入漏洞靶场</h1>
    <p>此靶场用于测试 VulnScanner 的命令注入检测能力，包含 time-based 和 output-based 两种检测目标。</p>

    <?php if ($safe && $cmd): ?>
    <div class="safe-mode">
        <strong>&#x1f6e1; 安全模式已启用</strong> — 命令通过 <code>escapeshellcmd()</code> 过滤后执行
    </div>
    <?php endif; ?>

    <?php if ($is_potential_injection && !$safe): ?>
    <div class="injection-warning">
        <strong>&#x26a0; 检测到疑似命令注入输出!</strong> — 响应中包含 OS 命令执行特征
    </div>
    <?php endif; ?>

    <!-- 注入点 1: GET cmd -->
    <div class="card">
        <h2>注入点 1: GET 参数 cmd (直接执行) &#x1f525;</h2>
        <p>用户输入直接传入 <code>shell_exec()</code>，无任何过滤。</p>
        <p>测试 Payload: <code>;id</code>, <code>|whoami</code>, <code>;sleep 5</code>, <code>%0aid</code></p>
        <div class="test-links">
            快速测试:
            <a href="?cmd=id">?cmd=id</a>
            <a href="?cmd=whoami">?cmd=whoami</a>
            <a href="?cmd=uname+-a">?cmd=uname -a</a>
            <a href="?cmd=dir">?cmd=dir</a>
            <a href="?safe=1&cmd=;id">?safe=1&cmd=;id (安全模式)</a>
        </div>
        <form method="GET">
            <input type="text" name="cmd" placeholder="输入命令 (例如: id, whoami, ls -la)" value="<?= htmlspecialchars($cmd) ?>">
            <label class="checkbox">
                <input type="checkbox" name="safe" value="1" <?= $safe ? 'checked' : '' ?>>
                安全模式 (escapeshellcmd)
            </label>
            <button type="submit">执行命令</button>
        </form>
    </div>

    <!-- 注入点 2: POST host Ping -->
    <div class="card">
        <h2>注入点 2: POST 参数 host (命令拼接) &#x1f525;</h2>
        <p>用户输入的 host 直接拼接到 <code>ping</code> 命令中: <code>ping -c 2 [host]</code></p>
        <p>测试 Payload: <code>127.0.0.1;id</code>, <code>127.0.0.1|whoami</code>, <code>127.0.0.1;sleep 5</code></p>
        <p>检测方式: Time-based (sleep) 或 Output-based (id/whoami 输出特征)</p>
        <form method="POST">
            <input type="text" name="host" placeholder="输入主机地址 (例如: 127.0.0.1 或 127.0.0.1;id)" value="<?= htmlspecialchars($host) ?>">
            <button type="submit">Ping</button>
        </form>
    </div>

    <?php if ($output !== ''): ?>
    <div class="card">
        <h2>命令输出:</h2>
        <pre><?= htmlspecialchars($output) ?></pre>
    </div>

    <!-- 注入检测诊断信息 (对扫描器可见) -->
    <div class="card" style="border-color: #0f3460;">
        <h2>扫描器诊断信息</h2>
        <table style="width:100%;border-collapse:collapse;">
            <tr style="border-bottom:1px solid #0f3460;">
                <td style="padding:5px;">输出长度</td>
                <td style="padding:5px;color:#53a8b6;"><?= strlen($output) ?> 字节</td>
            </tr>
            <tr style="border-bottom:1px solid #0f3460;">
                <td style="padding:5px;">包含 uid=</td>
                <td style="padding:5px;color:<?= stripos($output, 'uid=') !== false ? '#0f0' : '#f00' ?>;"><?= stripos($output, 'uid=') !== false ? '是' : '否' ?></td>
            </tr>
            <tr style="border-bottom:1px solid #0f3460;">
                <td style="padding:5px;">包含 root:</td>
                <td style="padding:5px;color:<?= stripos($output, 'root:') !== false ? '#0f0' : '#f00' ?>;"><?= stripos($output, 'root:') !== false ? '是' : '否' ?></td>
            </tr>
            <tr style="border-bottom:1px solid #0f3460;">
                <td style="padding:5px;">包含 gid=</td>
                <td style="padding:5px;color:<?= stripos($output, 'gid=') !== false ? '#0f0' : '#f00' ?>;"><?= stripos($output, 'gid=') !== false ? '是' : '否' ?></td>
            </tr>
            <tr>
                <td style="padding:5px;">潜在注入风险</td>
                <td style="padding:5px;color:<?= $is_potential_injection ? '#f00' : '#0f0' ?>;font-weight:bold;"><?= $is_potential_injection ? '是 — 检测到注入特征' : '否' ?></td>
            </tr>
        </table>
    </div>
    <?php endif; ?>
</body>
</html>
