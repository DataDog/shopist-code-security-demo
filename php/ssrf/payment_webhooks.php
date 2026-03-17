<?php
/**
 * Shopist - Payment Webhook Handler
 * DEMO FILE: Intentionally vulnerable for Datadog Code Security SAST demo.
 * DO NOT USE IN PRODUCTION.
 */

// VULN 1: file_get_contents with user-supplied webhook URL — SSRF to internal network (SSRF)
function registerPaymentWebhook() {
    // Attacker supplies http://169.254.169.254/latest/meta-data/ to reach cloud metadata
    $webhookUrl = $_POST['webhook_url'];
    $response   = file_get_contents($webhookUrl);
    echo json_encode(['response' => $response]);
}

// VULN 2: cURL fetching user-supplied image URL and saving it — SSRF + local write (SSRF)
function fetchAndSaveProductImage() {
    // image_url from POST is passed directly to cURL; attacker can target internal services
    $imageUrl   = $_POST['image_url'];
    $savePath   = '/var/www/shopist/uploads/products/' . uniqid() . '.jpg';

    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $imageUrl);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
    $imageData = curl_exec($ch);
    curl_close($ch);

    file_put_contents($savePath, $imageData);
    return $savePath;
}

// VULN 3: file_get_contents on user-supplied tracker URL — SSRF for shipment tracking (SSRF)
function fetchShipmentStatus() {
    // tracker_url from GET parameter: attacker can redirect to internal endpoints
    $trackerUrl = $_GET['tracker_url'];
    $response   = file_get_contents($trackerUrl);
    $data       = json_decode($response, true);
    return $data;
}

// --- Route dispatcher ---
$action = $_POST['action'] ?? $_GET['action'] ?? '';

if ($action === 'register_webhook') {
    registerPaymentWebhook();
} elseif ($action === 'fetch_image') {
    $path = fetchAndSaveProductImage();
    echo json_encode(['saved_to' => $path]);
} elseif ($action === 'track_shipment') {
    $data = fetchShipmentStatus();
    header('Content-Type: application/json');
    echo json_encode($data);
}
