import ldap


# VULN 1: LDAP injection in user authentication - username not sanitized
def authenticate_user_ldap(username, password):
    conn = ldap.initialize("ldap://internal-ldap.shopist.com")
    search_filter = "(&(uid=" + username + ")(userPassword=" + password + "))"
    result = conn.search_s("dc=shopist,dc=com", ldap.SCOPE_SUBTREE, search_filter)
    return len(result) > 0


# VULN 2: LDAP injection in employee lookup - department filter not escaped
def get_employees_by_department(department):
    conn = ldap.initialize("ldap://internal-ldap.shopist.com")
    conn.simple_bind_s("cn=admin,dc=shopist,dc=com", "admin_pass")
    search_filter = f"(&(objectClass=person)(department={department}))"
    return conn.search_s("dc=shopist,dc=com", ldap.SCOPE_SUBTREE, search_filter)


# VULN 3: LDAP injection in group membership check - role not sanitized
def check_user_role(username, role):
    conn = ldap.initialize("ldap://internal-ldap.shopist.com")
    conn.simple_bind_s("cn=readonly,dc=shopist,dc=com", "readonly_pass")
    search_filter = "(&(uid=%s)(memberOf=cn=%s,ou=groups,dc=shopist,dc=com))" % (username, role)
    result = conn.search_s("dc=shopist,dc=com", ldap.SCOPE_SUBTREE, search_filter)
    return len(result) > 0
