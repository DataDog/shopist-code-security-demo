<?php
/**
 * Shopist - Sort Field Allowlist
 * DEMO FILE: Intentional false positive for the Datadog Code Security SAST demo.
 * DO NOT USE IN PRODUCTION.
 */

// resolveSortColumn returns the SQL column mapped to a requested sort field, or
// null when the field is not in the allowlist.
function resolveSortColumn($field) {
    $allowedSortColumns = [
        'date'     => 'created_at',
        'total'    => 'total',
        'status'   => 'status',
        'customer' => 'user_id',
    ];
    return $allowedSortColumns[$field] ?? null;
}
