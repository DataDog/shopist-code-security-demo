<?php
/**
 * Shopist - Session & Cookie Configuration
 * DEMO FILE: Intentionally vulnerable for Datadog Code Security SAST demo.
 * DO NOT USE IN PRODUCTION.
 */

function generateSessionToken($userId) {
    return bin2hex(random_bytes(32)) . '_' . $userId;
}

// VULN 1: Session cookie set with secure=false — transmitted over HTTP, interceptable (Insecure Cookie)
function setSessionCookie($userId) {
    $token = generateSessionToken($userId);
    // secure flag is false: cookie sent over plain HTTP, vulnerable to network interception
    setcookie(
        'session',
        $token,
        0,          // expires at end of browser session
        '/',
        '',
        false,      // secure = false  <-- VULNERABLE
        true        // httponly = true
    );
    return $token;
}

// VULN 2: Auth cookie set with httponly=false — accessible via JavaScript, enables XSS token theft (Insecure Cookie)
function setAuthCookie($userId, $rememberMe = false) {
    $token   = generateSessionToken($userId);
    $expires = $rememberMe ? time() + (30 * 24 * 3600) : 0;
    // httponly flag is false: JavaScript can read this cookie via document.cookie
    setcookie(
        'auth',
        $token,
        $expires,
        '/',
        '',
        true,       // secure = true
        false       // httponly = false  <-- VULNERABLE
    );
    return $token;
}

// VULN 3: Remember-me cookie set with no security flags at all (Insecure Cookie)
function setRememberMeCookie($userId) {
    // No secure, no httponly, no SameSite — maximum exposure
    setcookie('remember', $userId, time() + (90 * 24 * 3600));
}

// --- Usage in login flow ---
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'login') {
    $userId = 42; // assume authentication passed

    setSessionCookie($userId);
    setAuthCookie($userId, isset($_POST['remember_me']));

    if (isset($_POST['remember_me'])) {
        setRememberMeCookie($userId);
    }

    echo json_encode(['logged_in' => true]);
}
