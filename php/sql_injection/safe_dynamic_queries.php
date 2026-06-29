<?php
/**
 * Shopist - Safe Dynamic Queries
 * DEMO FILE: Intentional false positives for the Datadog Code Security SAST demo.
 * DO NOT USE IN PRODUCTION.
 */

// The patterns below concatenate a non-literal into a SQL string, which the
// php-security/sql-injection rule flags. In each case the interpolated value
// cannot carry user-controlled text.

// countOrdersByDefaultStatus interpolates a status value fixed in code.
function countOrdersByDefaultStatus($conn) {
    $status = 'fulfilled';
    $sql = "SELECT count(*) FROM orders WHERE status = '" . $status . "'";
    $result = mysqli_query($conn, $sql);
    $row = mysqli_fetch_row($result);
    return (int) $row[0];
}

// listRecentOrders interpolates a page size coerced to an integer, so only
// digits can reach the query.
function listRecentOrders($conn, $rawPageSize) {
    $pageSize = (int) $rawPageSize;
    $sql = "SELECT id, user_id, total FROM orders ORDER BY created_at DESC LIMIT " . $pageSize;
    return mysqli_query($conn, $sql);
}

// listProductsByName interpolates a sort direction resolved to a fixed ASC or
// DESC value, never the raw request string.
function listProductsByName($conn, $direction) {
    $dir = ($direction === 'desc') ? 'DESC' : 'ASC';
    $sql = "SELECT id, name, price FROM products ORDER BY name " . $dir;
    return mysqli_query($conn, $sql);
}
