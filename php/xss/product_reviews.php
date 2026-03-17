<?php
/**
 * Shopist - Product Reviews
 * DEMO FILE: Intentionally vulnerable for Datadog Code Security SAST demo.
 * DO NOT USE IN PRODUCTION.
 */

$conn = mysqli_connect("localhost", "shopist_user", "shopist_pass", "shopist_db");

// VULN 1: Reflected XSS — $_GET['q'] echoed directly into HTML without encoding (XSS)
function renderSearchResults($conn) {
    // Search term reflected in page output without htmlspecialchars()
    echo "<h1>Results for: " . $_GET['q'] . "</h1>";

    $searchTerm = mysqli_real_escape_string($conn, $_GET['q']);
    $result = mysqli_query($conn, "SELECT p.id, p.name FROM products p WHERE p.name LIKE '%{$searchTerm}%'");
    echo "<ul>";
    while ($row = mysqli_fetch_assoc($result)) {
        echo "<li><a href='/product/" . $row['id'] . "'>" . $row['name'] . "</a></li>";
    }
    echo "</ul>";
}

// VULN 2: Stored XSS — review text fetched from DB and rendered without encoding (XSS)
function renderProductReviews($conn, $productId) {
    $pid    = (int)$productId;
    $result = mysqli_query($conn, "SELECT r.author_name, r.rating, r.text FROM reviews r WHERE r.product_id = $pid ORDER BY r.created_at DESC");
    echo "<ul class='reviews'>";
    while ($review = mysqli_fetch_assoc($result)) {
        // $review['text'] was stored from user input and is echoed unescaped — stored XSS
        echo "<li>";
        echo "<strong>" . $review['author_name'] . "</strong> (" . $review['rating'] . "/5)";
        echo "<p>" . $review['text'] . "</p>";
        echo "</li>";
    }
    echo "</ul>";
}

// VULN 3: Reflected XSS — login failure message includes unescaped POST username (XSS)
function handleLoginFailure() {
    // $_POST['username'] echoed back in the error message without escaping
    echo "<div class='error'>Login failed for: " . $_POST['username'] . "</div>";
    echo "<p>Please check your credentials and try again.</p>";
}

// --- Route dispatcher ---
$action = $_GET['action'] ?? '';

if ($action === 'search') {
    renderSearchResults($conn);
} elseif ($action === 'reviews') {
    $productId = (int)($_GET['product_id'] ?? 0);
    renderProductReviews($conn, $productId);
} elseif ($action === 'login_fail') {
    handleLoginFailure();
}
