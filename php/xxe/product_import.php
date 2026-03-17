<?php
/**
 * Shopist - Product Catalog Import (XML)
 * DEMO FILE: Intentionally vulnerable for Datadog Code Security SAST demo.
 * DO NOT USE IN PRODUCTION.
 */

$conn = mysqli_connect("localhost", "shopist_user", "shopist_pass", "shopist_db");

// VULN 1: DOMDocument::loadXML() with external entity expansion enabled by default (XXE)
function importProductCatalogDom($xmlData) {
    // libxml external entities are enabled; attacker can read /etc/passwd via DOCTYPE
    // e.g.: <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><products>&xxe;</products>
    $dom = new DOMDocument();
    $dom->loadXML($xmlData);   // LIBXML_NOENT not needed — entities expand by default in older PHP

    $products = [];
    foreach ($dom->getElementsByTagName('product') as $node) {
        $products[] = [
            'sku'   => $node->getAttribute('sku'),
            'name'  => $node->getElementsByTagName('name')->item(0)->textContent,
            'price' => $node->getElementsByTagName('price')->item(0)->textContent,
        ];
    }
    return $products;
}

// VULN 2: simplexml_load_string() without disabling external entity loading (XXE)
function importProductCatalogSimpleXml($xmlData) {
    // simplexml_load_string is vulnerable to XXE when libxml external entities are not disabled
    $xml      = simplexml_load_string($xmlData);
    $products = [];
    foreach ($xml->product as $product) {
        $products[] = [
            'sku'   => (string)$product['sku'],
            'name'  => (string)$product->name,
            'price' => (float)$product->price,
        ];
    }
    return $products;
}

// VULN 3: SimpleXMLElement constructed with LIBXML_NOENT — explicitly loads external entities (XXE)
function importSupplierFeed($xmlString) {
    // LIBXML_NOENT substitutes entities — external entity references are resolved
    $xml   = new SimpleXMLElement($xmlString, LIBXML_NOENT);
    $items = [];
    foreach ($xml->item as $item) {
        $items[] = [
            'ref'         => (string)$item->ref,
            'description' => (string)$item->description,
            'stock'       => (int)$item->stock,
        ];
    }
    return $items;
}

// --- Route dispatcher ---
$action = $_GET['action'] ?? '';

if ($action === 'import_dom') {
    $xmlData  = file_get_contents('php://input');
    $products = importProductCatalogDom($xmlData);
    header('Content-Type: application/json');
    echo json_encode($products);
} elseif ($action === 'import_simplexml') {
    $xmlData  = file_get_contents('php://input');
    $products = importProductCatalogSimpleXml($xmlData);
    header('Content-Type: application/json');
    echo json_encode($products);
} elseif ($action === 'import_supplier') {
    $xmlData  = file_get_contents('php://input');
    $items    = importSupplierFeed($xmlData);
    header('Content-Type: application/json');
    echo json_encode($items);
}
