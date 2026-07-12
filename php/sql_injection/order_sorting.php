<?php
/**
 * Shopist - Sorted Order Report (query layer)
 * DEMO FILE: Intentional false positive for the Datadog Code Security SAST demo.
 * DO NOT USE IN PRODUCTION.
 */

// listOrdersSorted returns an org's orders ordered by $sortColumn.
//
// An ORDER BY target cannot be a bound query parameter, so $sortColumn is
// concatenated into the SQL text. The org filter is passed as a bound
// parameter.
function listOrdersSorted($conn, $orgId, $sortColumn) {
    $sql = "SELECT id, user_id, total, status FROM orders WHERE user_id = ? ORDER BY " . $sortColumn;

    $stmt = mysqli_prepare($conn, $sql);
    mysqli_stmt_bind_param($stmt, "i", $orgId);
    mysqli_stmt_execute($stmt);
    $result = mysqli_stmt_get_result($stmt);

    $orders = [];
    while ($row = mysqli_fetch_assoc($result)) {
        $orders[] = $row;
    }
    return $orders;
}
