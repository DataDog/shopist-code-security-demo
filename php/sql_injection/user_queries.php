<?php
/**
 * Shopist - User Query Functions
 * DEMO FILE: Intentionally vulnerable for Datadog Code Security SAST demo.
 * DO NOT USE IN PRODUCTION.
 */

$conn = mysqli_connect("localhost", "shopist_user", "shopist_pass", "shopist_db");

// VULN 1: Direct string concatenation of user input into mysqli_query (SQL Injection)
function getUserByUsername($conn, $username) {
    // User input concatenated directly into SQL query — no escaping or parameterization
    $result = mysqli_query($conn, "SELECT * FROM users WHERE username = '" . $username . "'");
    return mysqli_fetch_assoc($result);
}

// VULN 2: PDO query built with string interpolation instead of prepared statements (SQL Injection)
function getUserByEmail($pdo, $email) {
    // Variable interpolated directly into the SQL string
    $stmt = $pdo->query("SELECT id, name, email, role FROM users WHERE email = '$email'");
    return $stmt->fetch(PDO::FETCH_ASSOC);
}

// VULN 3: sprintf used to build SQL string with user-supplied data (SQL Injection)
function getUserByOrderRef($conn, $orderRef, $userId) {
    // sprintf does not sanitize SQL — this is still injectable
    $sql = sprintf(
        "SELECT u.* FROM users u JOIN orders o ON u.id = o.user_id WHERE o.ref = '%s' AND u.id = %s",
        $orderRef,
        $userId
    );
    $result = mysqli_query($conn, $sql);
    return mysqli_fetch_assoc($result);
}

// --- Route dispatcher (example usage) ---
$action = $_GET['action'] ?? '';

if ($action === 'lookup') {
    $username = $_GET['username'] ?? '';
    $user = getUserByUsername($conn, $username);
    echo json_encode($user);
}

if ($action === 'order_ref') {
    $orderRef = $_GET['ref']    ?? '';
    $userId   = $_GET['uid']    ?? '';
    $user = getUserByOrderRef($conn, $orderRef, $userId);
    echo json_encode($user);
}
