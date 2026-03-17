import javax.naming.*;
import javax.naming.directory.*;
import java.util.Hashtable;

public class UserAuthentication {
    private static final String LDAP_URL = "ldap://ldap.shopist.internal:389";
    private static final String LDAP_BASE = "dc=shopist,dc=internal";

    private DirContext getLdapContext() throws NamingException {
        Hashtable<String, String> env = new Hashtable<>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, LDAP_URL);
        env.put(Context.SECURITY_AUTHENTICATION, "simple");
        env.put(Context.SECURITY_PRINCIPAL, "cn=svc-shopist,ou=service,dc=shopist,dc=internal");
        env.put(Context.SECURITY_CREDENTIALS, "svc-password");
        return new InitialDirContext(env);
    }

    // VULN 1: String concatenation in LDAP filter for user authentication
    public NamingEnumeration<SearchResult> authenticateUser(String username, String password) throws NamingException {
        DirContext ctx = getLdapContext();
        String filter = "(&(uid=" + username + ")(userPassword=" + password + "))";
        SearchControls controls = new SearchControls();
        controls.setSearchScope(SearchControls.SUBTREE_SCOPE);
        return ctx.search("ou=users," + LDAP_BASE, filter, controls);
    }

    // VULN 2: String.format in LDAP filter for employee record lookup
    public NamingEnumeration<SearchResult> lookupEmployee(String employeeId) throws NamingException {
        DirContext ctx = getLdapContext();
        String filter = String.format("(&(objectClass=person)(employeeNumber=%s))", employeeId);
        SearchControls controls = new SearchControls();
        controls.setSearchScope(SearchControls.SUBTREE_SCOPE);
        controls.setReturningAttributes(new String[]{"cn", "mail", "telephoneNumber", "department"});
        return ctx.search("ou=employees," + LDAP_BASE, filter, controls);
    }

    // VULN 3: String concatenation in LDAP group membership filter for role-based access
    public NamingEnumeration<SearchResult> getUserGroups(String username) throws NamingException {
        DirContext ctx = getLdapContext();
        String filter = "(&(objectClass=groupOfNames)(member=uid=" + username + ",ou=users," + LDAP_BASE + "))";
        SearchControls controls = new SearchControls();
        controls.setSearchScope(SearchControls.SUBTREE_SCOPE);
        controls.setReturningAttributes(new String[]{"cn", "description"});
        return ctx.search("ou=groups," + LDAP_BASE, filter, controls);
    }
}
