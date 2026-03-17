<?php
/**
 * Shopist - Order Query Functions
 * DEMO FILE: Intentionally vulnerable for Datadog Code Security SAST demo.
 * DO NOT USE IN PRODUCTION.
 */

$conn = mysqli_connect("localhost", "shopist_user", "shopist_pass", "shopist_db");

// VULN 1: String concatenation for order status query (SQL Injection)
function getOrdersByStatus($conn, $userId) {
    // $status comes from user input and is concatenated without escaping
    $status = $_GET['status'];
    $query = "SELECT * FROM orders WHERE user_id = " . $userId . " AND status = '" . $status . "' ORDER BY created_at DESC";
    $result = mysqli_query($conn, $query);
    $orders = [];
    while ($row = mysqli_fetch_assoc($result)) {
        $orders[] = $row;
    }
    return $orders;
}

// VULN 2: $_POST data inserted directly into an UPDATE SQL statement (SQL Injection)
function updateOrderAddress($conn) {
    // All fields sourced from $_POST with no sanitization
    $orderId        = $_POST['order_id'];
    $shippingAddr   = $_POST['shipping_address'];
    $city           = $_POST['city'];
    $postalCode     = $_POST['postal_code'];

    $sql = "UPDATE orders SET shipping_address = '" . $shippingAddr . "', city = '" . $city . "', postal_code = '" . $postalCode . "' WHERE id = " . $orderId;
    mysqli_query($conn, $sql);
}

// VULN 3: sprintf used by admin for order search — still injectable (SQL Injection)
function adminSearchOrders($conn) {
    // Admin search endpoint: customer email and date range from query string
    $email     = $_GET['email']      ?? '';
    $dateFrom  = $_GET['date_from']  ?? '2000-01-01';
    $dateTo    = $_GET['date_to']    ?? date('Y-m-d');

    // sprintf does not escape SQL metacharacters
    $sql = sprintf(
        "SELECT o.*, u.email FROM orders o JOIN users u ON o.user_id = u.id WHERE u.email = '%s' AND o.created_at BETWEEN '%s' AND '%s'",
        $email,
        $dateFrom,
        $dateTo
    );
    $result = mysqli_query($conn, $sql);
    $orders = [];
    while ($row = mysqli_fetch_assoc($result)) {
        $orders[] = $row;
    }
    return $orders;
}

// --- Route dispatcher ---
$action  = $_GET['action']  ?? '';
$userId  = $_SESSION['user_id'] ?? 0;

if ($action === 'by_status') {
    $orders = getOrdersByStatus($conn, $userId);
    header('Content-Type: application/json');
    echo json_encode($orders);
}

if ($action === 'update_address') {
    updateOrderAddress($conn);
    echo json_encode(['success' => true]);
}

if ($action === 'admin_search') {
    $orders = adminSearchOrders($conn);
    header('Content-Type: application/json');
    echo json_encode($orders);
}
