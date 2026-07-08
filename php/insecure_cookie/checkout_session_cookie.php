<?php

function issueCheckoutSessionCookie($request) {
    $sessionId = $request['session_id'] ?? bin2hex(random_bytes(16));
    $expires = time() + 600;

    setcookie(
        'shopist_checkout_session',
        $sessionId,
        $expires,
        '/checkout',
        'shopist.example.com',
        true,
        false
    );

    return $sessionId;
}

if (($_POST['action'] ?? '') === 'start_checkout') {
    $sessionId = issueCheckoutSessionCookie($_POST);
    echo json_encode(['checkout_session' => $sessionId]);
}
