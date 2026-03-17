require 'net/ldap'

LDAP_CONN = Net::LDAP.new(
  host: 'ldap.shopist.internal',
  port: 389,
  auth: { method: :simple, username: 'cn=admin,dc=shopist,dc=com', password: ENV['LDAP_ADMIN_PASSWORD'] }
)

# VULN 1: String interpolation in LDAP auth filter - attacker injects )(uid=*)( to bypass authentication
def authenticate_user(username, password)
  filter = Net::LDAP::Filter.construct("(&(uid=#{username})(userPassword=#{password}))")
  result = LDAP_CONN.search(base: 'ou=users,dc=shopist,dc=com', filter: filter)
  result&.first
end

# VULN 2: String format in employee lookup filter - LDAP injection via crafted employee_id
def lookup_employee(employee_id)
  filter_str = "(&(objectClass=person)(employeeNumber=%s))" % employee_id
  filter = Net::LDAP::Filter.construct(filter_str)
  result = LDAP_CONN.search(base: 'ou=employees,dc=shopist,dc=com', filter: filter)
  result&.map { |e| { name: e[:cn].first, email: e[:mail].first, dept: e[:department].first } }
end

# VULN 3: String concat in group membership filter - LDAP injection allows enumerating all groups
def get_user_groups(username)
  filter = Net::LDAP::Filter.construct("(&(objectClass=groupOfNames)(member=uid=" + username + ",ou=users,dc=shopist,dc=com))")
  result = LDAP_CONN.search(base: 'ou=groups,dc=shopist,dc=com', filter: filter)
  result&.map { |g| g[:cn].first }
end
