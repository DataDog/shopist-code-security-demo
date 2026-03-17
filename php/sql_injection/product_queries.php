<?php
/**
 * Shopist - Product Query Functions
 * DEMO FILE: Intentionally vulnerable for Datadog Code Security SAST demo.
 * DO NOT USE IN PRODUCTION.
 */

$conn = mysqli_connect("localhost", "shopist_user", "shopist_pass", "shopist_db");

// VULN 1: String concatenation in product search query using $_GET (SQL Injection)
function searchProducts($conn) {
    // $_GET['q'] inserted directly into the query without sanitization
    $searchTerm = $_GET['q'];
    $query = "SELECT id, name, price, stock FROM products WHERE name LIKE '%" . $searchTerm . "%' OR description LIKE '%" . $searchTerm . "%'";
    $result = mysqli_query($conn, $query);
    $products = [];
    while ($row = mysqli_fetch_assoc($result)) {
        $products[] = $row;
    }
    return $products;
}

// VULN 2: $_GET parameter used directly in SQL WHERE clause (SQL Injection)
function getProductById($conn) {
    // Product ID taken from query string and placed directly into SQL
    $productId = $_GET['id'];
    $result = mysqli_query($conn, "SELECT * FROM products WHERE id = " . $productId . " AND active = 1");
    return mysqli_fetch_assoc($result);
}

// VULN 3: Double-quoted string with variable interpolation in SQL (SQL Injection)
function getProductsByCategory($conn, $categorySlug) {
    $pdo = new PDO("mysql:host=localhost;dbname=shopist_db", "shopist_user", "shopist_pass");
    // Variable interpolated directly into SQL string — PDO provides no benefit here
    $stmt = $pdo->query("SELECT p.* FROM products p JOIN categories c ON p.category_id = c.id WHERE c.slug = '$categorySlug' ORDER BY p.created_at DESC");
    return $stmt->fetchAll(PDO::FETCH_ASSOC);
}

// --- Route dispatcher ---
$action = $_GET['action'] ?? '';

if ($action === 'search') {
    $results = searchProducts($conn);
    header('Content-Type: application/json');
    echo json_encode($results);
}

if ($action === 'detail') {
    $product = getProductById($conn);
    header('Content-Type: application/json');
    echo json_encode($product);
}

if ($action === 'category') {
    $slug = $_GET['category'] ?? '';
    $products = getProductsByCategory($conn, $slug);
    header('Content-Type: application/json');
    echo json_encode($products);
}
