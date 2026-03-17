<?php
/**
 * Shopist - Report Generator
 * DEMO FILE: Intentionally vulnerable for Datadog Code Security SAST demo.
 * DO NOT USE IN PRODUCTION.
 */

// VULN 1: passthru() with user-controlled URL passed to wkhtmltopdf (Command Injection)
function generateOrderPdf() {
    // $url is taken from POST and injected into the shell command without escaping
    $url       = $_POST['report_url'];
    $outputPdf = '/var/www/shopist/reports/order_report.pdf';
    passthru("wkhtmltopdf " . $url . " " . $outputPdf);
    readfile($outputPdf);
}

// VULN 2: exec() with user-supplied input and output file paths for document conversion (Command Injection)
function convertDocument($inputFile, $outputFile) {
    // Both file paths originate from request parameters and are passed to exec() unsanitized
    exec("pandoc " . $inputFile . " -o " . $outputFile, $output, $ret);
    return ['output' => $output, 'return_code' => $ret];
}

// VULN 3: popen() with user-controlled PDF filename passed to Ghostscript (Command Injection)
function renderPdfPreview() {
    // $pdfFile comes from $_GET and is appended to the shell command
    $pdfFile = $_GET['pdf_file'];
    $handle  = popen("gs -dBATCH -dNOPAUSE -sDEVICE=png16m -sOutputFile=preview.png " . $pdfFile, "r");
    if ($handle) {
        $output = stream_get_contents($handle);
        pclose($handle);
        echo $output;
    }
}

// --- Route dispatcher ---
$action = $_GET['action'] ?? '';

if ($action === 'pdf') {
    generateOrderPdf();
} elseif ($action === 'convert') {
    $inputFile  = $_POST['input_file']  ?? '';
    $outputFile = $_POST['output_file'] ?? '';
    $result = convertDocument($inputFile, $outputFile);
    echo json_encode($result);
} elseif ($action === 'preview') {
    renderPdfPreview();
}
