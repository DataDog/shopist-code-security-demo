<?php
/**
 * Shopist - Account Management Redirects
 * DEMO FILE: Intentionally vulnerable for Datadog Code Security SAST demo.
 * DO NOT USE IN PRODUCTION.
 */

session_start();

// VULN 1: header() redirect to unsanitized $_GET['redirect_to'] in password reset flow (Open Redirect)
function handlePasswordReset() {
    $token       = $_GET['token']       ?? '';
    $redirectTo  = $_GET['redirect_to'] ?? '/account/login';

    // Password reset logic ...
    // After resetting, redirect to attacker-specified URL
    header("Location: " . $redirectTo);
    exit();
}

// VULN 2: header() redirect to HTTP_REFERER in logout — Referer is attacker-controllable (Open Redirect)
function handleLogout() {
    // Destroy session
    $_SESSION = [];
    session_destroy();

    // HTTP_REFERER is set by the browser or attacker and should never be trusted for redirects
    $referer = $_SERVER['HTTP_REFERER'] ?? '/';
    header("Location: " . $referer);
    exit();
}

// VULN 3: header() redirect to unsanitized $_GET['callback_url'] in social account linking (Open Redirect)
function handleSocialAccountLink() {
    $provider    = $_GET['provider']     ?? '';
    $callbackUrl = $_GET['callback_url'] ?? '/account/settings';

    // Social OAuth linking logic ...
    // callback_url is user-supplied and used directly in the Location header
    header("Location: " . $callbackUrl);
    exit();
}

// --- Route dispatcher ---
$action = $_GET['action'] ?? '';

if ($action === 'reset_password') {
    handlePasswordReset();
} elseif ($action === 'logout') {
    handleLogout();
} elseif ($action === 'link_social') {
    handleSocialAccountLink();
}
