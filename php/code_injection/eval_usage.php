<?php
/**
 * Shopist - Dynamic Rule Evaluation
 * DEMO FILE: Intentionally vulnerable for Datadog Code Security SAST demo.
 * DO NOT USE IN PRODUCTION.
 */

// VULN 1: eval() executed on user-supplied formula for discount calculation (Code Injection)
function calculateDynamicDiscount($basePrice) {
    // formula comes from GET: e.g., ?formula=system('cat /etc/passwd')
    $formula = $_GET['formula'];
    $price   = $basePrice;
    eval('$discount = ' . $formula . ';');
    return $price - ($discount ?? 0);
}

// VULN 2: eval() on a user-supplied shipping rule expression (Code Injection)
function applyShippingRule($weight, $destination) {
    // Merchant-supplied rule executed as PHP: $_POST['rule'] = 'system("id")'
    $rule = $_POST['rule'];
    eval('$result = ' . $rule . ';');
    return $result ?? 0;
}

// VULN 3: preg_replace with /e modifier executes replacement as PHP code (Code Injection — PHP < 7)
function formatProductDescription($template) {
    // The /e modifier causes the replacement string to be eval'd — removed in PHP 7.0
    // Attacker controls $_GET['code']: ?code=system('whoami')
    $code        = $_GET['code'];
    $description = preg_replace('/.*/e', $code, $template);
    return $description;
}

// --- Route dispatcher ---
$action = $_GET['action'] ?? '';

if ($action === 'discount') {
    $basePrice   = (float)($_GET['price'] ?? 100);
    $finalPrice  = calculateDynamicDiscount($basePrice);
    echo json_encode(['final_price' => $finalPrice]);
} elseif ($action === 'shipping') {
    $weight      = (float)($_POST['weight']      ?? 1.0);
    $destination = $_POST['destination'] ?? 'domestic';
    $cost        = applyShippingRule($weight, $destination);
    echo json_encode(['shipping_cost' => $cost]);
} elseif ($action === 'format') {
    $template = $_GET['template'] ?? 'A great product. ';
    $result   = formatProductDescription($template);
    echo $result;
}
