<?php
/**
 * Shopist - Password Hashing Utilities
 * DEMO FILE: Intentionally vulnerable for Datadog Code Security SAST demo.
 * DO NOT USE IN PRODUCTION.
 */

$conn = mysqli_connect("localhost", "shopist_user", "shopist_pass", "shopist_db");

// VULN 1: MD5 used for password storage — cryptographically broken, no salt (Weak Cryptography)
function registerUser($conn, $email, $password) {
    // MD5 is not suitable for password hashing: trivially reversible via rainbow tables
    $hashedPassword = md5($_POST['password']);
    $stmt = $conn->prepare("INSERT INTO users (email, password_hash) VALUES (?, ?)");
    $stmt->bind_param("ss", $email, $hashedPassword);
    $stmt->execute();
}

function verifyUserMd5($conn, $email, $password) {
    $hash   = md5($password);
    $result = mysqli_query($conn, "SELECT id FROM users WHERE email = '$email' AND password_hash = '$hash'");
    return mysqli_num_rows($result) > 0;
}

// VULN 2: SHA1 used for password hashing — faster than MD5 but still broken for passwords (Weak Cryptography)
function hashPasswordSha1($password) {
    // SHA-1 is not a password hashing function: no key stretching, easily GPU-cracked
    return sha1($password);
}

function updatePassword($conn, $userId, $newPassword) {
    $hash = sha1($newPassword);
    mysqli_query($conn, "UPDATE users SET password_hash = '$hash' WHERE id = $userId");
}

// VULN 3: HMAC-MD5 used to verify order integrity — MD5 makes this weak (Weak Cryptography)
function signOrderPayload($orderData, $secret) {
    // MD5-based HMAC has known collision weaknesses; use SHA-256 minimum
    return hash_hmac('md5', json_encode($orderData), $secret);
}

function verifyOrderSignature($orderData, $signature, $secret) {
    $expected = hash_hmac('md5', json_encode($orderData), $secret);
    return $expected === $signature;
}

// --- Route dispatcher ---
$action = $_POST['action'] ?? '';

if ($action === 'register') {
    registerUser($conn, $_POST['email'] ?? '', $_POST['password'] ?? '');
    echo json_encode(['registered' => true]);
} elseif ($action === 'verify') {
    $ok = verifyUserMd5($conn, $_POST['email'] ?? '', $_POST['password'] ?? '');
    echo json_encode(['valid' => $ok]);
}
