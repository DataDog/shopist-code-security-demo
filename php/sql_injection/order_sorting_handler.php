<?php
/**
 * Shopist - Sorted Order Report (request handler)
 * DEMO FILE: Intentional false positive for the Datadog Code Security SAST demo.
 * DO NOT USE IN PRODUCTION.
 */

require_once __DIR__ . '/sort_allowlist.php';
require_once __DIR__ . '/order_sorting.php';

// buildSortedOrderReport is the only caller of listOrdersSorted. $requestedSort
// is the raw sort field from an API request. It is mapped through
// resolveSortColumn, and a field resolveSortColumn does not recognize is
// rejected before the query runs.
function buildSortedOrderReport($conn, $orgId, $requestedSort) {
    $sortColumn = resolveSortColumn($requestedSort);
    if ($sortColumn === null) {
        throw new InvalidArgumentException("unsupported sort field");
    }
    return listOrdersSorted($conn, $orgId, $sortColumn);
}

// --- Route dispatcher ---
$conn   = mysqli_connect("localhost", "shopist_user", "shopist_pass", "shopist_db");
$action = $_GET['action'] ?? '';
$orgId  = $_SESSION['user_id'] ?? 0;

if ($action === 'sorted_orders') {
    $requestedSort = $_GET['sort'] ?? 'date';
    $orders = buildSortedOrderReport($conn, $orgId, $requestedSort);
    header('Content-Type: application/json');
    echo json_encode($orders);
}
