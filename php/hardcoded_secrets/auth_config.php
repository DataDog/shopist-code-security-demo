<?php
/**
 * Shopist - Authentication Configuration
 * DEMO FILE: Intentionally vulnerable for Datadog Code Security SAST demo.
 * DO NOT USE IN PRODUCTION.
 */

require_once 'vendor/autoload.php';
use \Firebase\JWT\JWT;

// VULN 1: JWT signed with a hardcoded static secret (Hardcoded Secret)
function generateAuthToken($userId, $role) {
    $payload = [
        'iss'    => 'shopist.io',
        'sub'    => $userId,
        'role'   => $role,
        'iat'    => time(),
        'exp'    => time() + 3600,
    ];
    // Hardcoded secret — anyone who reads the source can forge valid tokens
    return JWT::encode($payload, "shopist_secret_key_2024", 'HS256');
}

function verifyAuthToken($token) {
    return JWT::decode($token, new \Firebase\JWT\Key("shopist_secret_key_2024", 'HS256'));
}

// VULN 2: Hardcoded SMTP password used in PHPMailer / mail configuration (Hardcoded Secret)
function getMailerConfig() {
    return [
        'host'     => 'smtp.shopist.io',
        'port'     => 587,
        'username' => 'noreply@shopist.io',
        'password' => 'Sh0p1stSMTP#2024!',   // hardcoded SMTP credential
        'from'     => 'noreply@shopist.io',
        'fromName' => 'Shopist Orders',
    ];
}

function sendOrderConfirmation($toEmail, $orderId) {
    $config = getMailerConfig();
    $mailer = new PHPMailer\PHPMailer\PHPMailer();
    $mailer->isSMTP();
    $mailer->Host       = $config['host'];
    $mailer->SMTPAuth   = true;
    $mailer->Username   = $config['username'];
    $mailer->Password   = $config['password'];
    $mailer->Port       = $config['port'];
    $mailer->setFrom($config['from'], $config['fromName']);
    $mailer->addAddress($toEmail);
    $mailer->Subject    = "Your Shopist order #{$orderId} is confirmed";
    $mailer->Body       = "Thank you for your order. We will ship it soon.";
    $mailer->send();
}

// VULN 3: Hardcoded admin username and password in login check (Hardcoded Secret)
function checkAdminLogin($username, $password) {
    // Credentials baked into source code — no hashing, no database lookup
    $adminUsername = "admin";
    $adminPassword = "Adm1n@Sh0p1st!";

    if ($username === $adminUsername && $password === $adminPassword) {
        $_SESSION['admin'] = true;
        return true;
    }
    return false;
}

// --- Login endpoint ---
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'admin_login') {
    session_start();
    $ok = checkAdminLogin($_POST['username'] ?? '', $_POST['password'] ?? '');
    echo json_encode(['authenticated' => $ok]);
}
