<?php
/**
 * IDOR (Insecure Direct Object Reference) 越权漏洞靶场
 *
 * 包含多个可被枚举的 API 端点，无任何认证检查：
 * 1. /api/users/{id} — 返回不同用户的 JSON 数据
 * 2. /api/orders/{id} — 返回不同订单的 JSON 数据
 * 3. /api/documents/{id} — 返回不同文档信息
 * 4. /api/invoices/{id} — 返回不同发票信息
 *
 * 所有端点都基于 URL 中的数字 ID 直接查询数据，
 * 没有任何身份验证或授权检查。
 * 攻击者只需修改 ID 即可查看其他用户的数据。
 */

// ========== 模拟用户数据库 ==========
$users_db = [
    1 => [
        'id' => 1,
        'username' => 'admin',
        'email' => 'admin@example.com',
        'phone' => '13800001111',
        'address' => '北京市朝阳区建国路100号',
        'role' => 'administrator',
        'created_at' => '2024-01-15 08:30:00',
        'last_login' => '2026-06-20 09:15:00',
    ],
    2 => [
        'id' => 2,
        'username' => 'zhangsan',
        'email' => 'zhangsan@qq.com',
        'phone' => '13912345678',
        'address' => '上海市浦东新区张江高科技园区',
        'role' => 'user',
        'created_at' => '2024-03-22 14:20:00',
        'last_login' => '2026-06-19 18:30:00',
    ],
    3 => [
        'id' => 3,
        'username' => 'lisi',
        'email' => 'lisi@163.com',
        'phone' => '13698765432',
        'address' => '广州市天河区珠江新城',
        'role' => 'user',
        'created_at' => '2024-05-10 10:00:00',
        'last_login' => '2026-06-18 12:00:00',
    ],
    100 => [
        'id' => 100,
        'username' => 'wangwu',
        'email' => 'wangwu@gmail.com',
        'phone' => '13511112222',
        'address' => '深圳市南山区科技园',
        'role' => 'vip_user',
        'created_at' => '2024-08-01 09:00:00',
        'last_login' => '2026-06-20 08:00:00',
    ],
    101 => [
        'id' => 101,
        'username' => 'zhaoliu',
        'email' => 'zhaoliu@outlook.com',
        'phone' => '13333334444',
        'address' => '杭州市西湖区文三路',
        'role' => 'user',
        'created_at' => '2024-10-15 16:45:00',
        'last_login' => '2026-06-17 20:00:00',
    ],
];

$orders_db = [
    1 => [
        'order_id' => 10001,
        'user_id' => 1,
        'username' => 'admin',
        'order_date' => '2026-06-15',
        'order_status' => 'completed',
        'total_amount' => 2999.00,
        'payment_method' => 'credit_card',
        'card_last4' => '1234',
        'shipping_address' => '北京市朝阳区建国路100号',
        'items' => [
            ['product_name' => 'MacBook Pro 16"', 'quantity' => 1, 'unit_price' => 2999.00],
        ],
    ],
    2 => [
        'order_id' => 10002,
        'user_id' => 2,
        'username' => 'zhangsan',
        'order_date' => '2026-06-16',
        'order_status' => 'shipped',
        'total_amount' => 599.00,
        'payment_method' => 'alipay',
        'card_last4' => '',
        'shipping_address' => '上海市浦东新区张江高科技园区',
        'tracking_number' => 'SF1234567890',
        'items' => [
            ['product_name' => 'AirPods Pro', 'quantity' => 1, 'unit_price' => 599.00],
        ],
    ],
    3 => [
        'order_id' => 10003,
        'user_id' => 3,
        'username' => 'lisi',
        'order_date' => '2026-06-17',
        'order_status' => 'processing',
        'total_amount' => 15800.00,
        'payment_method' => 'wechat_pay',
        'card_last4' => '',
        'shipping_address' => '广州市天河区珠江新城',
        'items' => [
            ['product_name' => 'iPhone 16 Pro Max', 'quantity' => 1, 'unit_price' => 12999.00],
            ['product_name' => 'MagSafe Charger', 'quantity' => 1, 'unit_price' => 399.00],
            ['product_name' => 'AppleCare+', 'quantity' => 1, 'unit_price' => 2402.00],
        ],
    ],
    100 => [
        'order_id' => 10100,
        'user_id' => 100,
        'username' => 'wangwu',
        'order_date' => '2026-06-18',
        'order_status' => 'delivered',
        'total_amount' => 2499.00,
        'payment_method' => 'credit_card',
        'card_last4' => '5678',
        'shipping_address' => '深圳市南山区科技园',
        'tracking_number' => 'SF0987654321',
        'items' => [
            ['product_name' => 'iPad Air', 'quantity' => 1, 'unit_price' => 2499.00],
        ],
    ],
    101 => [
        'order_id' => 10101,
        'user_id' => 101,
        'username' => 'zhaoliu',
        'order_date' => '2026-06-19',
        'order_status' => 'pending',
        'total_amount' => 349.00,
        'payment_method' => 'alipay',
        'card_last4' => '',
        'shipping_address' => '杭州市西湖区文三路',
        'items' => [
            ['product_name' => 'Apple Pencil 2', 'quantity' => 1, 'unit_price' => 349.00],
        ],
    ],
];

$invoices_db = [
    1 => [
        'invoice_id' => 'INV-2026-001',
        'user_id' => 2,
        'username' => 'zhangsan',
        'invoice_date' => '2026-06-16',
        'due_date' => '2026-07-16',
        'amount' => 599.00,
        'tax' => 77.87,
        'total' => 676.87,
        'status' => 'paid',
        'billing_address' => '上海市浦东新区张江高科技园区',
        'items' => [['description' => 'AirPods Pro', 'amount' => 599.00]],
    ],
    2 => [
        'invoice_id' => 'INV-2026-002',
        'user_id' => 3,
        'username' => 'lisi',
        'invoice_date' => '2026-06-17',
        'due_date' => '2026-07-17',
        'amount' => 15800.00,
        'tax' => 2054.00,
        'total' => 17854.00,
        'status' => 'unpaid',
        'billing_address' => '广州市天河区珠江新城',
        'items' => [
            ['description' => 'iPhone 16 Pro Max', 'amount' => 12999.00],
            ['description' => 'MagSafe Charger', 'amount' => 399.00],
            ['description' => 'AppleCare+', 'amount' => 2402.00],
        ],
    ],
    3 => [
        'invoice_id' => 'INV-2026-003',
        'user_id' => 100,
        'username' => 'wangwu',
        'invoice_date' => '2026-06-18',
        'due_date' => '2026-07-18',
        'amount' => 2499.00,
        'tax' => 324.87,
        'total' => 2823.87,
        'status' => 'paid',
        'billing_address' => '深圳市南山区科技园',
        'items' => [['description' => 'iPad Air', 'amount' => 2499.00]],
    ],
];

$documents_db = [
    1 => [
        'document_id' => 'DOC-001',
        'owner_id' => 1,
        'owner_name' => 'admin',
        'filename' => '2024年度财务报告.pdf',
        'file_size' => '2.4 MB',
        'upload_date' => '2025-01-20',
        'category' => 'financial',
        'confidential' => true,
    ],
    2 => [
        'document_id' => 'DOC-002',
        'owner_id' => 2,
        'owner_name' => 'zhangsan',
        'filename' => '劳动合同_张三.pdf',
        'file_size' => '1.1 MB',
        'upload_date' => '2025-03-15',
        'category' => 'hr',
        'confidential' => true,
    ],
    3 => [
        'document_id' => 'DOC-003',
        'owner_id' => 3,
        'owner_name' => 'lisi',
        'filename' => '项目方案_v3.docx',
        'file_size' => '856 KB',
        'upload_date' => '2025-06-10',
        'category' => 'project',
        'confidential' => false,
    ],
    100 => [
        'document_id' => 'DOC-100',
        'owner_id' => 100,
        'owner_name' => 'wangwu',
        'filename' => '客户名单_2025Q4.xlsx',
        'file_size' => '320 KB',
        'upload_date' => '2025-10-01',
        'category' => 'sales',
        'confidential' => true,
    ],
];

// ========== 路由分发 ==========
$request_uri = $_SERVER['REQUEST_URI'] ?? '/';
$path = parse_url($request_uri, PHP_URL_PATH);
$path = rtrim($path, '/');

// 移除可能的 index.php 前缀
$path = preg_replace('#^/index\.php#', '', $path);

header('Content-Type: application/json; charset=utf-8');
// 禁用缓存，确保每次请求都是新的
header('Cache-Control: no-store, no-cache, must-revalidate');
header('Pragma: no-cache');

// 注意: 以下所有接口均无任何身份验证和授权检查
// 这是一个典型的 IDOR 漏洞场景

// ============================================
// API: /api/users/{id}
// 返回用户信息 JSON — 无认证
// ============================================
if (preg_match('#^/api/users/(\d+)$#', $path, $matches)) {
    $user_id = (int)$matches[1];

    if (isset($users_db[$user_id])) {
        echo json_encode($users_db[$user_id], JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
    } else {
        http_response_code(404);
        echo json_encode(['error' => '用户不存在', 'user_id' => $user_id], JSON_UNESCAPED_UNICODE);
    }
    exit;
}

// API: /api/user/{id} (别名)
if (preg_match('#^/api/user/(\d+)$#', $path, $matches)) {
    $user_id = (int)$matches[1];

    if (isset($users_db[$user_id])) {
        echo json_encode($users_db[$user_id], JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
    } else {
        http_response_code(404);
        echo json_encode(['error' => '用户不存在', 'user_id' => $user_id], JSON_UNESCAPED_UNICODE);
    }
    exit;
}

// ============================================
// API: /api/orders/{id}
// 返回订单信息 JSON — 无认证
// ============================================
if (preg_match('#^/api/orders/(\d+)$#', $path, $matches)) {
    $order_index = (int)$matches[1];

    if (isset($orders_db[$order_index])) {
        echo json_encode($orders_db[$order_index], JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
    } else {
        http_response_code(404);
        echo json_encode(['error' => '订单不存在', 'order_index' => $order_index], JSON_UNESCAPED_UNICODE);
    }
    exit;
}

// API: /api/order/{id} (别名)
if (preg_match('#^/api/order/(\d+)$#', $path, $matches)) {
    $order_index = (int)$matches[1];

    if (isset($orders_db[$order_index])) {
        echo json_encode($orders_db[$order_index], JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
    } else {
        http_response_code(404);
        echo json_encode(['error' => '订单不存在', 'order_index' => $order_index], JSON_UNESCAPED_UNICODE);
    }
    exit;
}

// ============================================
// API: /api/invoices/{id}
// 返回发票信息 JSON — 无认证
// ============================================
if (preg_match('#^/api/invoices/(\d+)$#', $path, $matches)) {
    $invoice_index = (int)$matches[1];

    if (isset($invoices_db[$invoice_index])) {
        echo json_encode($invoices_db[$invoice_index], JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
    } else {
        http_response_code(404);
        echo json_encode(['error' => '发票不存在', 'invoice_index' => $invoice_index], JSON_UNESCAPED_UNICODE);
    }
    exit;
}

// ============================================
// API: /api/documents/{id}
// 返回文档信息 JSON — 无认证
// ============================================
if (preg_match('#^/api/documents/(\d+)$#', $path, $matches)) {
    $doc_index = (int)$matches[1];

    if (isset($documents_db[$doc_index])) {
        echo json_encode($documents_db[$doc_index], JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
    } else {
        http_response_code(404);
        echo json_encode(['error' => '文档不存在', 'doc_index' => $doc_index], JSON_UNESCAPED_UNICODE);
    }
    exit;
}

// ============================================
// 如果没有任何端点匹配
// ============================================
http_response_code(404);
echo json_encode(['error' => '端点不存在', 'path' => $path], JSON_UNESCAPED_UNICODE);
