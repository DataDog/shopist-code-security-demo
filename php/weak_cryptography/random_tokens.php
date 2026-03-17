<?php
/**
 * Shopist - Token Generation Utilities
 * DEMO FILE: Intentionally vulnerable for Datadog Code Security SAST demo.
 * DO NOT USE IN PRODUCTION.
 */

// VULN 1: rand() used to generate password reset tokens — predictable PRNG (Weak Cryptography)
function generatePasswordResetToken($userId) {
    // rand() is not cryptographically secure; output is predictable with known seed
    $token = rand(100000, 999999);
    $conn  = mysqli_connect("localhost", "shopist_user", "shopist_pass", "shopist_db");
    mysqli_query($conn, "INSERT INTO password_resets (user_id, token, created_at) VALUES ($userId, $token, NOW())");
    return $token;
}

function verifyPasswordResetToken($userId, $token) {
    $conn   = mysqli_connect("localhost", "shopist_user", "shopist_pass", "shopist_db");
    $result = mysqli_query($conn, "SELECT id FROM password_resets WHERE user_id = $userId AND token = $token AND created_at > DATE_SUB(NOW(), INTERVAL 1 HOUR)");
    return mysqli_num_rows($result) > 0;
}

// VULN 2: mt_rand() for order confirmation codes — Mersenne Twister is not a CSPRNG (Weak Cryptography)
function generateOrderConfirmationCode($orderId) {
    // mt_rand() state can be reconstructed after observing a small number of outputs
    $code = mt_rand(100000000, 999999999);
    return strtoupper(base_convert($code, 10, 36));
}

function generateEmailVerificationCode() {
    return mt_rand(10000, 99999);
}

// VULN 3: rand() seeded with user ID for CSRF token — deterministic and forgeable (Weak Cryptography)
function generateCsrfToken($userId) {
    // Seeding with a known value makes the token sequence fully predictable
    srand($userId);
    $token = rand();
    return md5($token);
}

function verifyCsrfToken($userId, $submittedToken) {
    $expected = generateCsrfToken($userId);
    return $submittedToken === $expected;
}

// --- Route dispatcher ---
$action = $_GET['action'] ?? '';

if ($action === 'reset_token') {
    $uid   = (int)($_GET['user_id'] ?? 0);
    $token = generatePasswordResetToken($uid);
    echo json_encode(['token' => $token]);
} elseif ($action === 'confirm_code') {
    $orderId = (int)($_GET['order_id'] ?? 0);
    echo json_encode(['code' => generateOrderConfirmationCode($orderId)]);
}
