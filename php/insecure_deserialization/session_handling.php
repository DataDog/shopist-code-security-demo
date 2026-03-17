<?php
/**
 * Shopist - Session Handling
 * DEMO FILE: Intentionally vulnerable for Datadog Code Security SAST demo.
 * DO NOT USE IN PRODUCTION.
 */

session_start();

// VULN 1: unserialize() on session data that may have been tampered with (Insecure Deserialization)
function loadUserFromSession() {
    // If session storage (e.g. Redis, files) is compromised, attacker can inject a serialized payload
    $userData = $_SESSION['user_data'];
    $user     = unserialize($userData);
    return $user;
}

function saveUserToSession($user) {
    $_SESSION['user_data'] = serialize($user);
}

// VULN 2: yaml_parse() on user-supplied config — YAML can deserialize PHP objects (Insecure Deserialization)
function applyUserPreferences() {
    // yaml_parse() may instantiate arbitrary PHP objects via YAML tags (e.g., !php/object)
    $yamlConfig  = $_POST['config'];
    $preferences = yaml_parse($yamlConfig);

    if (isset($preferences['theme'])) {
        $_SESSION['theme'] = $preferences['theme'];
    }
    if (isset($preferences['currency'])) {
        $_SESSION['currency'] = $preferences['currency'];
    }
    return $preferences;
}

// VULN 3: unserialize() on base64-decoded GET token parameter (Insecure Deserialization)
function restoreGuestCheckoutState() {
    // The 'token' query parameter contains a base64-encoded serialized PHP object
    $token = $_GET['token'];
    $state = unserialize(base64_decode($token));
    return $state;
}

// --- Route dispatcher ---
$action = $_POST['action'] ?? $_GET['action'] ?? '';

if ($action === 'load_user') {
    $user = loadUserFromSession();
    echo json_encode(['name' => $user->name ?? 'unknown']);
} elseif ($action === 'preferences') {
    $prefs = applyUserPreferences();
    echo json_encode(['applied' => true, 'prefs' => $prefs]);
} elseif ($action === 'restore_checkout') {
    $state = restoreGuestCheckoutState();
    echo json_encode(['state' => $state]);
}
