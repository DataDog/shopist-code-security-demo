<?php
/**
 * Shopist - Product Data Enrichment
 * DEMO FILE: Intentionally vulnerable for Datadog Code Security SAST demo.
 * DO NOT USE IN PRODUCTION.
 */

// VULN 1: file_get_contents on a user-supplied URL for product metadata enrichment (SSRF)
function importProductFromExternalSource() {
    // $source is user-supplied: file_get_contents will follow any URL including internal ones
    $source   = $_GET['source'];
    $response = file_get_contents($source);
    $product  = json_decode($response, true);
    return $product;
}

// VULN 2: cURL executing against a user-supplied RSS feed URL for product updates (SSRF)
function fetchProductRssFeed() {
    // feed_url from POST is passed to cURL with no allowlist validation
    $feedUrl = $_POST['feed_url'];

    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $feedUrl);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 10);
    $response = curl_exec($ch);
    curl_close($ch);

    $xml = simplexml_load_string($response);
    $items = [];
    foreach ($xml->channel->item as $item) {
        $items[] = [
            'title'       => (string)$item->title,
            'description' => (string)$item->description,
            'link'        => (string)$item->link,
        ];
    }
    return $items;
}

// VULN 3: file_get_contents with user-controlled API base URL concatenated with a path (SSRF)
function fetchCategoryFromApi() {
    // api_base comes from GET; attacker can point to internal metadata services or admin APIs
    $apiBase  = $_GET['api_base'];
    $response = file_get_contents($apiBase . '/products');
    return json_decode($response, true);
}

// --- Route dispatcher ---
$action = $_GET['action'] ?? '';

if ($action === 'import_product') {
    $product = importProductFromExternalSource();
    header('Content-Type: application/json');
    echo json_encode($product);
} elseif ($action === 'rss_feed') {
    $items = fetchProductRssFeed();
    header('Content-Type: application/json');
    echo json_encode($items);
} elseif ($action === 'api_fetch') {
    $data = fetchCategoryFromApi();
    header('Content-Type: application/json');
    echo json_encode($data);
}
