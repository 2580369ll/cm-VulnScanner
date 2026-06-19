<?php
/**
 * 路径穿越 / LFI 漏洞靶场
 *
 * 包含两个注入点：
 * 1. GET 参数 file — 传入 include() 进行文件包含
 * 2. GET 参数 template — 传入 file_get_contents() 读取文件
 *
 * 故意暴露类似 Linux 系统文件的输出，使扫描器能检测到路径穿越特征。
 */

$file = $_GET['file'] ?? '';
$template = $_GET['template'] ?? '';
$action = $_GET['action'] ?? '';
$test_passwd = isset($_GET['test_passwd']);

$output = '';
$error = '';
$include_output = '';

// ====== 模拟系统文件内容 ======
define('FAKE_PASSWD', "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nbin:x:2:2:bin:/bin:/usr/sbin/nologin\nsys:x:3:3:sys:/dev:/usr/sbin/nologin\nsync:x:4:65534:sync:/bin:/bin/sync\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n");

define('FAKE_SHADOW', "root:\$6\$salt\$hash:19000:0:99999:7:::\ndaemon:*:19000:0:99999:7:::\nbin:*:19000:0:99999:7:::\nsys:*:19000:0:99999:7:::\nwww-data:*:19000:0:99999:7:::\n");

define('FAKE_WIN_INI', "; for 16-bit app support\n[fonts]\n[extensions]\n[mci extensions]\n[files]\n[Mail]\nMAPI=1\nCMC=1\nCMCDLLNAME32=mapi32.dll\nCMCDLLNAME=mapi.dll\nMAPIX=1\nMAPIXVER=1.0.0.1\n");

define('FAKE_HOSTS', "127.0.0.1\tlocalhost\n127.0.1.1\tvuln-scanner-target\n\n::1\tlocalhost ip6-localhost ip6-loopback\n");

define('FAKE_PROC_ENVIRON', "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\nHOME=/var/www\nUSER=www-data\nSHELL=/bin/bash\nHTTP_HOST=vuln-target.local\nSERVER_NAME=vuln-target.local\nDOCUMENT_ROOT=/var/www/html\n");

// ====== 注入点 1: GET file 参数 (include) ======
if ($file) {
    // 漏洞: 直接 include 用户输入
    if ($file === '/etc/passwd' || strpos($file, 'passwd') !== false) {
        $output = FAKE_PASSWD;
        $include_output = "<!-- include success -->\n" . FAKE_PASSWD;
    } elseif ($file === '/etc/shadow' || strpos($file, 'shadow') !== false) {
        $output = FAKE_SHADOW;
        $include_output = "<!-- include success -->\n" . FAKE_SHADOW;
    } elseif ($file === '/etc/hosts' || strpos($file, 'hosts') !== false) {
        $output = FAKE_HOSTS;
        $include_output = "<!-- include success -->\n" . FAKE_HOSTS;
    } elseif (strpos($file, 'environ') !== false) {
        $output = FAKE_PROC_ENVIRON;
        $include_output = "<!-- include success -->\n" . FAKE_PROC_ENVIRON;
    } elseif (strpos($file, 'win.ini') !== false) {
        $output = FAKE_WIN_INI;
        $include_output = "<!-- include success -->\n" . FAKE_WIN_INI;
    } elseif (preg_match('/\.\.\/|\.\.\\\\/', $file)) {
        // 通用路径穿越匹配
        if (stripos($file, 'passwd') !== false) {
            $output = FAKE_PASSWD;
        } elseif (stripos($file, 'shadow') !== false) {
            $output = FAKE_SHADOW;
        } elseif (stripos($file, 'win.ini') !== false) {
            $output = FAKE_WIN_INI;
        } elseif (stripos($file, 'environ') !== false) {
            $output = FAKE_PROC_ENVIRON;
        } else {
            $output = "root:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n";
        }
        $include_output = "<!-- path traversal success: {$file} -->\n" . $output;
    } else {
        $output = "<!-- failed to include '{$file}' -->\n";
        $error = "Warning: include({$file}): failed to open stream: No such file or directory";
        $include_output = $output;
    }
}

// ====== 注入点 2: GET template 参数 (file_get_contents) ======
if ($template) {
    $content = false;
    if ($template === '/etc/passwd' || strpos($template, 'passwd') !== false) {
        $content = FAKE_PASSWD;
    } elseif ($template === '/etc/shadow' || strpos($template, 'shadow') !== false) {
        $content = FAKE_SHADOW;
    } elseif ($template === '/etc/hosts' || strpos($template, 'hosts') !== false) {
        $content = FAKE_HOSTS;
    } elseif (strpos($template, 'win.ini') !== false) {
        $content = FAKE_WIN_INI;
    } elseif (strpos($template, 'environ') !== false) {
        $content = FAKE_PROC_ENVIRON;
    } elseif (preg_match('/\.\.\/|\.\.\\\\/', $template)) {
        if (stripos($template, 'passwd') !== false) {
            $content = FAKE_PASSWD;
        } elseif (stripos($template, 'shadow') !== false) {
            $content = FAKE_SHADOW;
        } elseif (stripos($template, 'win.ini') !== false) {
            $content = FAKE_WIN_INI;
        } else {
            $content = "root:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n";
        }
    }
    if ($content === false) {
        $error = "Warning: file_get_contents({$template}): failed to open stream: No such file or directory";
        $output = "";
    } else {
        $output = $content;
    }
}

// ====== 独立测试模式 ======
if ($test_passwd) {
    header('Content-Type: text/plain');
    echo FAKE_PASSWD;
    exit;
}

if ($action === 'source') {
    header('Content-Type: text/plain');
    echo "<?php\n// Simulated php://filter output\n// Base64 decoded source of index.php\n";
    echo '$file = $_GET[\'file\'] ?? \'\';' . "\n";
    echo '$template = $_GET[\'template\'] ?? \'\';' . "\n";
    echo '// Vulnerable: include($file);' . "\n";
    exit;
}
?>
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <title>路径穿越 / LFI 靶场 — VulnScanner Test</title>
    <style>
        * { box-sizing: border-box; }
        body { font-family: -apple-system, sans-serif; max-width: 900px; margin: 40px auto; padding: 20px; background: #1a1a2e; color: #eee; }
        h1 { color: #e94560; }
        .card { background: #16213e; padding: 20px; margin: 20px 0; border-radius: 8px; border: 1px solid #0f3460; }
        .card h2 { margin-top: 0; color: #53a8b6; }
        input, button { padding: 10px; border-radius: 4px; border: 1px solid #0f3460; background: #1a1a2e; color: #eee; width: 100%; margin: 5px 0; }
        button { background: #e94560; cursor: pointer; border: none; font-weight: bold; }
        button:hover { background: #c23152; }
        pre { background: #0a0a1a; padding: 15px; border-radius: 4px; overflow-x: auto; white-space: pre-wrap; color: #0f0; font-size: 13px; }
        .error-box { background: #330000; border: 2px solid #ff4444; color: #ff6666; padding: 10px; border-radius: 4px; margin: 10px 0; }
        .success-box { background: #003300; border: 2px solid #00cc00; color: #99ff99; padding: 10px; border-radius: 4px; margin: 10px 0; }
        .test-links { margin: 10px 0; }
        .test-links a { display: inline-block; color: #53a8b6; margin: 0 12px 6px 0; text-decoration: none; font-size: 14px; }
        .test-links a:hover { color: #e94560; }
        code { color: #53a8b6; background: #0a0a1a; padding: 2px 6px; border-radius: 3px; }
        table.diag { width: 100%; border-collapse: collapse; }
        table.diag td { padding: 6px 8px; border-bottom: 1px solid #0f3460; }
        .match-yes { color: #00ff00; font-weight: bold; }
        .match-no { color: #ff4444; }
    </style>
</head>
<body>
    <h1>&#x1f4c2; 路径穿越 / LFI 漏洞靶场</h1>
    <p>此靶场用于测试 VulnScanner 的路径穿越检测能力。成功穿越时返回模拟系统文件内容（含 <code>root:x:0:0:</code> 等特征）。</p>

    <?php if ($error): ?>
    <div class="error-box"><strong>&#x274c; 错误:</strong> <?= htmlspecialchars($error) ?></div>
    <?php endif; ?>

    <?php if ($include_output && $output && !$error): ?>
    <div class="success-box"><strong>&#x2705; 路径穿越成功!</strong> — 返回了文件内容</div>
    <?php endif; ?>

    <div class="card">
        <h2>注入点 1: GET 参数 file (include)</h2>
        <p>用户输入传入 <code>include()</code>，无过滤。</p>
        <div class="test-links">
            <a href="?file=/etc/passwd">?file=/etc/passwd</a>
            <a href="?file=../../../../etc/passwd">?file=../../../../etc/passwd</a>
            <a href="?file=../../etc/shadow">?file=../../etc/shadow</a>
            <a href="?file=../../../windows/win.ini">?file=../../../windows/win.ini</a>
            <a href="?file=/proc/self/environ">?file=/proc/self/environ</a>
            <a href="?action=source">?action=source</a>
        </div>
        <form method="GET">
            <input type="text" name="file" placeholder="路径 (例如: ../../etc/passwd)" value="<?= htmlspecialchars($file) ?>">
            <button type="submit">包含文件</button>
        </form>
    </div>

    <div class="card">
        <h2>注入点 2: GET 参数 template (file_get_contents)</h2>
        <p>用户输入传入 <code>file_get_contents()</code>，无过滤。</p>
        <div class="test-links">
            <a href="?template=../../../../etc/passwd">?template=../../../../etc/passwd</a>
            <a href="?template=/etc/passwd">?template=/etc/passwd</a>
        </div>
        <form method="GET">
            <input type="text" name="template" placeholder="路径 (例如: ../../etc/passwd)" value="<?= htmlspecialchars($template) ?>">
            <button type="submit">读取文件</button>
        </form>
    </div>

    <?php if ($output): ?>
    <div class="card">
        <h2>文件内容:</h2>
        <pre><?= htmlspecialchars($include_output ?: $output) ?></pre>
    </div>

    <div class="card">
        <h2>扫描器诊断</h2>
        <table class="diag">
            <tr><td>输出长度</td><td style="color:#53a8b6;"><?= strlen($include_output ?: $output) ?> 字节</td></tr>
            <tr><td>包含 <code>root:x:0:0:</code></td><td class="<?= stripos($include_output ?: $output, 'root:x:0:0:') !== false ? 'match-yes' : 'match-no' ?>"><?= stripos($include_output ?: $output, 'root:x:0:0:') !== false ? '是' : '否' ?></td></tr>
            <tr><td>包含 <code>[extensions]</code></td><td class="<?= stripos($include_output ?: $output, '[extensions]') !== false ? 'match-yes' : 'match-no' ?>"><?= stripos($include_output ?: $output, '[extensions]') !== false ? '是' : '否' ?></td></tr>
            <tr><td>包含 <code>[fonts]</code></td><td class="<?= stripos($include_output ?: $output, '[fonts]') !== false ? 'match-yes' : 'match-no' ?>"><?= stripos($include_output ?: $output, '[fonts]') !== false ? '是' : '否' ?></td></tr>
            <tr><td>包含 <code>for 16-bit app support</code></td><td class="<?= stripos($include_output ?: $output, 'for 16-bit app support') !== false ? 'match-yes' : 'match-no' ?>"><?= stripos($include_output ?: $output, 'for 16-bit app support') !== false ? '是' : '否' ?></td></tr>
            <tr><td>包含 <code>/bin/bash</code></td><td class="<?= stripos($include_output ?: $output, '/bin/bash') !== false ? 'match-yes' : 'match-no' ?>"><?= stripos($include_output ?: $output, '/bin/bash') !== false ? '是' : '否' ?></td></tr>
            <tr><td>包含 <code>www-data</code></td><td class="<?= stripos($include_output ?: $output, 'www-data') !== false ? 'match-yes' : 'match-no' ?>"><?= stripos($include_output ?: $output, 'www-data') !== false ? '是' : '否' ?></td></tr>
            <tr><td style="padding-top:10px;font-weight:bold;">路径穿越检测结果</td><td style="padding-top:10px;font-weight:bold;color:<?= ($include_output && !$error) ? '#00ff00' : '#ff4444' ?>;"><?= ($include_output && !$error) ? '成功 — 检测到文件内容特征' : ($error ? '触发错误' : '—') ?></td></tr>
        </table>
    </div>
    <?php endif; ?>

    <div class="card">
        <h2>验证模式: 直接返回模拟 passwd</h2>
        <p><a href="?test_passwd=1">?test_passwd=1</a> — 返回模拟 /etc/passwd 内容，不含 HTML。</p>
    </div>
</body>
</html>
