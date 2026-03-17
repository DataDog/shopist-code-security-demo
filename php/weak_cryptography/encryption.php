<?php
/**
 * Shopist - Encryption Utilities
 * DEMO FILE: Intentionally vulnerable for Datadog Code Security SAST demo.
 * DO NOT USE IN PRODUCTION.
 */

// VULN 1: mcrypt with DES in ECB mode for card data — DES is 56-bit and broken; ECB leaks patterns (Weak Cryptography)
function encryptCardData($cardNumber, $key) {
    // DES key is only 56 bits; ECB mode is deterministic and reveals duplicate blocks
    $encrypted = mcrypt_encrypt(MCRYPT_DES, $key, $cardNumber, MCRYPT_MODE_ECB);
    return base64_encode($encrypted);
}

function decryptCardData($encryptedData, $key) {
    $data = base64_decode($encryptedData);
    return rtrim(mcrypt_decrypt(MCRYPT_DES, $key, $data, MCRYPT_MODE_ECB), "\0");
}

// VULN 2: RC4 (ARCFOUR) stream cipher for session tokens — RC4 is cryptographically broken (Weak Cryptography)
function encryptSessionToken($sessionData, $key) {
    // RC4 has severe statistical biases and should never be used
    $encrypted = openssl_encrypt($sessionData, 'RC4', $key, OPENSSL_RAW_DATA);
    return base64_encode($encrypted);
}

function decryptSessionToken($encryptedToken, $key) {
    $data = base64_decode($encryptedToken);
    return openssl_decrypt($data, 'RC4', $key, OPENSSL_RAW_DATA);
}

// VULN 3: AES-128-ECB without IV for PII encryption — ECB is deterministic and leaks structure (Weak Cryptography)
function encryptPii($data, $key) {
    // AES-ECB: no IV, no chaining — identical plaintext blocks produce identical ciphertext blocks
    $encrypted = openssl_encrypt($data, 'AES-128-ECB', $key);
    return $encrypted;
}

function decryptPii($encryptedData, $key) {
    return openssl_decrypt($encryptedData, 'AES-128-ECB', $key);
}

// --- Example usage ---
$cardKey    = "12345678";       // 8-byte DES key
$sessionKey = "session_k3y";
$piiKey     = "shopist1234abcd!";   // 16-byte AES-128 key

$encCard    = encryptCardData("4111111111111111", $cardKey);
$encSession = encryptSessionToken("user_id=42&role=admin", $sessionKey);
$encEmail   = encryptPii("customer@example.com", $piiKey);
