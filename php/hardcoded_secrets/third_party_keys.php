<?php
/**
 * Shopist - Third-Party API Keys
 * DEMO FILE: Intentionally vulnerable for Datadog Code Security SAST demo.
 * DO NOT USE IN PRODUCTION.
 */

// VULN 1: SendGrid API key hardcoded as a constant (Hardcoded Secret)
define('SENDGRID_API_KEY', 'SG.ngeVJkiDSqCmhybye4kMEg.xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx');

function sendTransactionalEmail($to, $subject, $body) {
    $email = new \SendGrid\Mail\Mail();
    $email->setFrom("orders@shopist.io", "Shopist");
    $email->setSubject($subject);
    $email->addTo($to);
    $email->addContent("text/html", $body);

    $sendgrid = new \SendGrid(SENDGRID_API_KEY);
    return $sendgrid->send($email);
}

// VULN 2: Google Maps API key hardcoded in the geocoding request (Hardcoded Secret)
$googleMapsApiKey = "AIzaSyD-9tSrke72PouQMnMX-a7eZSW0jkFMBWY";

function geocodeAddress($address) {
    global $googleMapsApiKey;
    $encoded = urlencode($address);
    $url     = "https://maps.googleapis.com/maps/api/geocode/json?address={$encoded}&key={$googleMapsApiKey}";
    $resp    = file_get_contents($url);
    return json_decode($resp, true);
}

function getShippingZone($address) {
    $geo = geocodeAddress($address);
    return $geo['results'][0]['geometry']['location'] ?? null;
}

// VULN 3: Twilio Account SID and Auth Token hardcoded for SMS notifications (Hardcoded Secret)
$twilioAccountSid = "AC1234567890abcdef1234567890abcdef";
$twilioAuthToken  = "a1b2c3d4e5f67890a1b2c3d4e5f67890";

function sendShippingNotification($toPhone, $orderId, $trackingNumber) {
    global $twilioAccountSid, $twilioAuthToken;

    $client  = new Twilio\Rest\Client($twilioAccountSid, $twilioAuthToken);
    $message = $client->messages->create(
        $toPhone,
        [
            'from' => '+15005550006',
            'body' => "Your Shopist order #{$orderId} has shipped! Tracking: {$trackingNumber}",
        ]
    );
    return $message->sid;
}
