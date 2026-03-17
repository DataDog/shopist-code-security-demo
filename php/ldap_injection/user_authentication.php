<?php
/**
 * Shopist - LDAP User Authentication (Corporate SSO)
 * DEMO FILE: Intentionally vulnerable for Datadog Code Security SAST demo.
 * DO NOT USE IN PRODUCTION.
 */

$ldapHost = "ldap://shopist-ad.internal";
$ldapBase = "dc=shopist,dc=internal";

// VULN 1: LDAP search filter built by concatenating unsanitized username and password (LDAP Injection)
function authenticateEmployee($conn, $base, $username, $password) {
    // Attacker can inject: username = *)(uid=*)(\00  to bypass authentication
    $filter = "(&(uid=" . $username . ")(userPassword=" . $password . "))";
    $result = ldap_search($conn, $base, $filter, ['uid', 'cn', 'mail', 'memberOf']);
    $entries = ldap_get_entries($conn, $result);
    return ($entries['count'] > 0) ? $entries[0] : null;
}

// VULN 2: LDAP filter for employee lookup built with string formatting — no escaping (LDAP Injection)
function lookupEmployeeByBadgeId($conn, $base, $badgeId) {
    // $badgeId from GET parameter concatenated directly into the filter string
    $badgeId = $_GET['badge_id'];
    $filter  = sprintf("(&(objectClass=person)(employeeNumber=%s))", $badgeId);
    $result  = ldap_search($conn, $base, $filter, ['cn', 'mail', 'department', 'title']);
    $entries = ldap_get_entries($conn, $result);
    return ($entries['count'] > 0) ? $entries[0] : null;
}

// VULN 3: Group membership LDAP filter concatenated from user-supplied group name (LDAP Injection)
function checkGroupMembership($conn, $base, $userDn) {
    // group_name from POST is embedded in the filter — allows wildcard injection
    $groupName = $_POST['group_name'];
    $filter    = "(&(objectClass=groupOfNames)(cn=" . $groupName . ")(member=" . $userDn . "))";
    $result    = ldap_search($conn, $base, $filter, ['cn', 'description']);
    $entries   = ldap_get_entries($conn, $result);
    return ($entries['count'] > 0);
}

// --- Route dispatcher ---
$ldapConn = ldap_connect($ldapHost);
ldap_set_option($ldapConn, LDAP_OPT_PROTOCOL_VERSION, 3);
ldap_bind($ldapConn, "cn=svc-shopist,dc=shopist,dc=internal", "svc_password");

$action = $_POST['action'] ?? $_GET['action'] ?? '';

if ($action === 'login') {
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';
    $employee = authenticateEmployee($ldapConn, $ldapBase, $username, $password);
    echo json_encode(['authenticated' => ($employee !== null)]);
} elseif ($action === 'lookup') {
    $employee = lookupEmployeeByBadgeId($ldapConn, $ldapBase, '');
    echo json_encode($employee);
} elseif ($action === 'check_group') {
    $userDn = $_POST['user_dn'] ?? '';
    $isMember = checkGroupMembership($ldapConn, $ldapBase, $userDn);
    echo json_encode(['member' => $isMember]);
}
