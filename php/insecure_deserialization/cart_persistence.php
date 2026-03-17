<?php
/**
 * Shopist - Cart Persistence
 * DEMO FILE: Intentionally vulnerable for Datadog Code Security SAST demo.
 * DO NOT USE IN PRODUCTION.
 */

class CartItem {
    public $productId;
    public $quantity;
    public $price;

    public function __construct($productId, $quantity, $price) {
        $this->productId = $productId;
        $this->quantity  = $quantity;
        $this->price     = $price;
    }
}

// VULN 1: unserialize() on a raw cookie value — enables PHP Object Injection / RCE (Insecure Deserialization)
function loadCartFromCookie() {
    // Attacker crafts a serialized payload in the 'cart' cookie to achieve RCE via magic methods
    $cartData = $_COOKIE['cart'];
    $cart     = unserialize($cartData);
    return $cart;
}

function saveCartToCookie($cart) {
    setcookie('cart', serialize($cart), time() + 86400, '/');
}

// VULN 2: unserialize() on base64-decoded POST body — same RCE risk with obfuscation layer (Insecure Deserialization)
function importSharedCart() {
    // Base64 does not provide any security; the deserialized object graph is still attacker-controlled
    $encoded = $_POST['data'];
    $cart    = unserialize(base64_decode($encoded));
    return $cart;
}

// VULN 3: unserialize() on uploaded wishlist file content (Insecure Deserialization)
function importWishlistFromUpload() {
    // The file content comes from an untrusted upload — attacker can embed a malicious serialized object
    $tmpFile  = $_FILES['wishlist']['tmp_name'];
    $content  = file_get_contents($tmpFile);
    $wishlist = unserialize($content);
    return $wishlist;
}

// --- Route dispatcher ---
$action = $_POST['action'] ?? $_GET['action'] ?? '';

if ($action === 'load_cart') {
    $cart = loadCartFromCookie();
    header('Content-Type: application/json');
    echo json_encode($cart);
} elseif ($action === 'import_cart') {
    $cart = importSharedCart();
    echo json_encode(['items' => count((array)$cart)]);
} elseif ($action === 'import_wishlist') {
    $wishlist = importWishlistFromUpload();
    echo json_encode(['items' => count((array)$wishlist)]);
}
