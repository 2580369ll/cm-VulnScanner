<?php
/**
 * 信息泄露漏洞靶场
 *
 * 模拟一个忘记清理敏感文件的 Web 应用：
 * - 故意暴露 .git/config、.env、备份文件等
 * - 提供一个"意外暴露"的文件列表页面
 * - 包含调试端点
 */

// 模拟"意外"暴露 phpinfo
if (isset($_GET['debug']) && $_GET['debug'] === 'phpinfo') {
    phpinfo();
    exit;
}

// 模拟 Actuator 风格的 health 端点
if (isset($_GET['actuator']) && $_GET['actuator'] === 'health') {
    header('Content-Type: application/json');
    echo json_encode([
        'status' => 'UP',
        'components' => [
            'db' => ['status' => 'UP', 'details' => ['database' => 'MySQL', 'hello' => 1]],
            'redis' => ['status' => 'UP', 'details' => ['version' => '6.2.6']],
            'diskSpace' => ['status' => 'UP', 'details' => ['total' => 250685575168, 'free' => 125342687744]],
        ],
    ]);
    exit;
}

// "意外"暴露的配置文件列表
$exposed_files = [
    '.git/config'         => 'Git 仓库配置 — 包含仓库 URL 和分支信息',
    '.env'                => '环境变量文件 — 包含数据库密码、API密钥等凭证',
    'index.php.bak'       => 'index.php 的备份 — 可能包含旧版代码和注释',
    'web.config.bak'      => 'IIS web.config 备份 — ASP.NET 应用配置',
    'error.log'           => '错误日志 — 可能包含路径、数据库错误信息',
    'debug.log'           => '调试日志 — 可能包含调试信息和敏感数据',
    '.vscode/settings.json' => 'VS Code 编辑器配置',
    '.DS_Store'           => 'macOS 系统文件 — 包含目录结构信息',
];

// 检查访客是否尝试访问 .git/config
$git_config_path = __DIR__ . '/.git/config';
$env_path = __DIR__ . '/.env';
$requested_path = $_GET['path'] ?? '';

if ($requested_path === '.git/config' && file_exists($git_config_path)) {
    header('Content-Type: text/plain');
    readfile($git_config_path);
    exit;
}

if ($requested_path === '.env' && file_exists($env_path)) {
    header('Content-Type: text/plain');
    readfile($env_path);
    exit;
}

?>
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <title>公司内部管理系统 — VulnScanner Info Test</title>
    <style>
        * { box-sizing: border-box; }
        body {
            font-family: -apple-system, sans-serif;
            max-width: 900px;
            margin: 40px auto;
            padding: 20px;
            background: #1a1a2e;
            color: #eee;
        }
        h1 { color: #e94560; }
        .header-bar {
            background: linear-gradient(135deg, #16213e, #0f3460);
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 20px;
            border-left: 4px solid #e94560;
        }
        .card {
            background: #16213e;
            padding: 20px;
            margin: 20px 0;
            border-radius: 8px;
            border: 1px solid #0f3460;
        }
        .card h2 {
            margin-top: 0;
            color: #53a8b6;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 10px 0;
        }
        th, td {
            padding: 10px 12px;
            text-align: left;
            border-bottom: 1px solid #0f3460;
        }
        th {
            color: #53a8b6;
            background: #0f3460;
        }
        tr:hover {
            background: rgba(83, 168, 182, 0.1);
        }
        .badge {
            display: inline-block;
            padding: 3px 8px;
            border-radius: 3px;
            font-size: 11px;
            font-weight: bold;
        }
        .badge-danger { background: #e94560; color: white; }
        .badge-warning { background: #f0a500; color: #1a1a2e; }
        .badge-info { background: #53a8b6; color: #1a1a2e; }
        a { color: #53a8b6; text-decoration: none; }
        a:hover { text-decoration: underline; }
        .warning-box {
            background: #fff3cd;
            color: #856404;
            padding: 15px;
            border-radius: 5px;
            border: 1px solid #ffc107;
            margin: 10px 0;
            font-size: 14px;
        }
        code {
            background: #0f3460;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
            font-size: 13px;
        }
        .file-icon {
            margin-right: 8px;
            font-size: 16px;
        }
        footer {
            margin-top: 30px;
            padding-top: 15px;
            border-top: 1px solid #0f3460;
            font-size: 12px;
            color: #666;
            text-align: center;
        }
    </style>
</head>
<body>
    <div class="header-bar">
        <h1 style="margin:0;color:white;">Company Internal Portal</h1>
        <p style="margin:5px 0 0 0;color:#aaa;">Version 2.4.1 | Environment: production | Server: Apache/2.4.41</p>
    </div>

    <div class="card">
        <h2>系统公告</h2>
        <div class="warning-box">
            <strong>注意：</strong> 系统刚刚完成迁移，部分配置文件可能尚未清理。
            管理员将在近期处理。请勿访问以下文件。
        </div>
    </div>

    <!-- "意外"暴露的文件列表 -->
    <div class="card">
        <h2>项目文件列表</h2>
        <p style="font-size:13px;color:#888;">以下文件在当前目录中，部分文件可能包含敏感信息：</p>
        <table>
            <thead>
                <tr>
                    <th>文件名</th>
                    <th>说明</th>
                    <th>风险</th>
                    <th>操作</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($exposed_files as $filename => $description): ?>
                <tr>
                    <td>
                        <span class="file-icon">
                            <?php
                            $icon = '📄';
                            if (strpos($filename, '.git/') === 0) $icon = '🔧';
                            elseif (strpos($filename, '.env') === 0) $icon = '🔑';
                            elseif (strpos($filename, '.bak') !== false) $icon = '💾';
                            elseif (strpos($filename, '.log') !== false) $icon = '📋';
                            elseif (strpos($filename, '.DS_Store') === 0) $icon = '🍎';
                            echo $icon;
                            ?>
                        </span>
                        <code><?= htmlspecialchars($filename) ?></code>
                    </td>
                    <td style="font-size:13px;"><?= htmlspecialchars($description) ?></td>
                    <td>
                        <?php if (strpos($filename, '.env') === 0 || strpos($filename, '.git/') === 0): ?>
                            <span class="badge badge-danger">高危</span>
                        <?php elseif (strpos($filename, '.bak') !== false || strpos($filename, '.log') !== false): ?>
                            <span class="badge badge-warning">中危</span>
                        <?php else: ?>
                            <span class="badge badge-info">低危</span>
                        <?php endif; ?>
                    </td>
                    <td>
                        <a href="?path=<?= urlencode($filename) ?>">查看内容</a>
                    </td>
                </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    </div>

    <!-- 系统状态面板 -->
    <div class="card">
        <h2>系统状态</h2>
        <table>
            <tr>
                <td><strong>服务状态</strong></td>
                <td><span style="color:#4caf50;">● 运行中</span></td>
            </tr>
            <tr>
                <td><strong>数据库连接</strong></td>
                <td><span style="color:#4caf50;">● MySQL 8.0 — 正常</span></td>
            </tr>
            <tr>
                <td><strong>Redis 缓存</strong></td>
                <td><span style="color:#4caf50;">● Redis 6.2 — 正常</span></td>
            </tr>
            <tr>
                <td><strong>PHP 版本</strong></td>
                <td><?= phpversion() ?></td>
            </tr>
            <tr>
                <td><strong>磁盘空间</strong></td>
                <td>Total: 250GB | Used: 125GB | Free: 125GB</td>
            </tr>
            <tr>
                <td><strong>运行时间</strong></td>
                <td>15 days 6 hours 32 minutes</td>
            </tr>
        </table>
    </div>

    <!-- 调试入口（"隐藏"但不完全隐藏） -->
    <div class="card">
        <h2>开发者工具</h2>
        <p style="font-size:13px;color:#888;">仅供开发人员使用：</p>
        <ul>
            <li><a href="?debug=phpinfo">PHP Info →</a></li>
            <li><a href="?actuator=health">Health Check API →</a></li>
            <li><a href="/.env">环境变量配置 (.env) →</a> <span style="color:orange;">* 可能暴露</span></li>
            <li><a href="/.git/config">Git 配置 →</a> <span style="color:orange;">* 可能暴露</span></li>
        </ul>
    </div>

    <footer>
        Company Internal Portal &copy; 2024 | Powered by PHP <?= phpversion() ?>
    </footer>
</body>
</html>
