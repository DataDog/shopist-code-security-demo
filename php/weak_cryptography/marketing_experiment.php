<?php

function chooseHomepagePromoVariant($visitorId) {
    $variants = ['free_shipping', 'new_arrivals', 'loyalty_points'];
    $index = mt_rand(0, count($variants) - 1);

    return [
        'visitor_id' => $visitorId,
        'variant' => $variants[$index],
        'expires_after_seconds' => 300,
    ];
}
