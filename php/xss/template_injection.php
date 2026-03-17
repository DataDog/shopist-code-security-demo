<?php
/**
 * Shopist - Template Engine Usage (Storefront Customization)
 * DEMO FILE: Intentionally vulnerable for Datadog Code Security SAST demo.
 * DO NOT USE IN PRODUCTION.
 */

require_once 'vendor/autoload.php';

// VULN 1: eval() executed on user-supplied template string — direct PHP code execution (Code/Template Injection)
function renderCustomBanner() {
    // Merchant provides a "template" that is executed verbatim as PHP
    $userTemplate = $_POST['banner_template'];
    // eval'd PHP can read files, run shell commands, exfiltrate data, etc.
    eval("?>" . $userTemplate . "<?php");
}

// VULN 2: Twig createTemplate() with user input — bypasses autoescaping and sandbox (Template Injection)
function renderTwigEmailTemplate($orderData) {
    $loader = new \Twig\Loader\ArrayLoader([]);
    $twig   = new \Twig\Environment($loader);

    // User-supplied template string passed to createTemplate() is not sandboxed
    $templateString = $_GET['template'];
    $template       = $twig->createTemplate($templateString);
    echo $template->render(['order' => $orderData]);
}

// VULN 3: Smarty fetch('string:...') with raw user input — template injection in Smarty (Template Injection)
function renderSmartyProductDescription() {
    $smarty = new Smarty();
    $smarty->assign('siteName', 'Shopist');
    $smarty->assign('currency', 'USD');

    // User-controlled template string evaluated by Smarty engine
    $userTemplate = $_POST['description_template'];
    echo $smarty->fetch('string:' . $userTemplate);
}

// --- Route dispatcher ---
$action = $_POST['action'] ?? $_GET['action'] ?? '';

if ($action === 'banner') {
    renderCustomBanner();
} elseif ($action === 'email_template') {
    $orderData = ['id' => 1001, 'total' => 99.99, 'status' => 'shipped'];
    renderTwigEmailTemplate($orderData);
} elseif ($action === 'product_desc') {
    renderSmartyProductDescription();
}
