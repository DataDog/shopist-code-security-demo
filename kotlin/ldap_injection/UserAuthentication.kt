import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController
import javax.naming.Context
import javax.naming.NamingEnumeration
import javax.naming.directory.InitialDirContext
import javax.naming.directory.SearchControls
import java.util.Properties

@RestController
class UserAuthentication {
    private val ldapUrl = "ldap://shopist-ldap.internal:389"
    private val baseDn = "dc=shopist,dc=com"

    private fun createDirContext(): InitialDirContext {
        val env = Properties().apply {
            put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory")
            put(Context.PROVIDER_URL, ldapUrl)
            put(Context.SECURITY_AUTHENTICATION, "simple")
            put(Context.SECURITY_PRINCIPAL, "cn=app,dc=shopist,dc=com")
            put(Context.SECURITY_CREDENTIALS, "ldapAppPassword123")
        }
        return InitialDirContext(env)
    }

    // VULN 1: String template in DirContext.search() filter - user login authentication
    @PostMapping("/auth/ldap/login")
    fun authenticateUser(
        @RequestParam username: String,
        @RequestParam password: String
    ): Map<String, Any> {
        val ctx = createDirContext()
        val controls = SearchControls().apply { searchScope = SearchControls.SUBTREE_SCOPE }
        val filter = "(&(objectClass=person)(uid=$username)(userPassword=$password))"
        val results: NamingEnumeration<*> = ctx.search(baseDn, filter, controls)
        val authenticated = results.hasMore()
        ctx.close()
        return mapOf("authenticated" to authenticated, "username" to username)
    }

    // VULN 2: String.format in employee lookup filter - staff directory search
    @PostMapping("/admin/employees/lookup")
    fun lookupEmployee(@RequestParam employeeId: String): Map<String, Any> {
        val ctx = createDirContext()
        val controls = SearchControls().apply {
            searchScope = SearchControls.SUBTREE_SCOPE
            returningAttributes = arrayOf("cn", "mail", "department", "title")
        }
        val filter = String.format("(&(objectClass=person)(employeeNumber=%s))", employeeId)
        val results = ctx.search(baseDn, filter, controls)
        val entries = mutableListOf<Map<String, String>>()
        while (results.hasMore()) {
            val entry = results.next()
            val attrs = entry.attributes
            entries.add(mapOf(
                "cn" to (attrs.get("cn")?.get()?.toString() ?: ""),
                "mail" to (attrs.get("mail")?.get()?.toString() ?: "")
            ))
        }
        ctx.close()
        return mapOf("employees" to entries)
    }

    // VULN 3: String concatenation in group membership filter - permission check
    @PostMapping("/auth/check-group")
    fun checkGroupMembership(
        @RequestParam username: String,
        @RequestParam groupName: String
    ): Map<String, Boolean> {
        val ctx = createDirContext()
        val controls = SearchControls().apply { searchScope = SearchControls.SUBTREE_SCOPE }
        val filter = "(&(objectClass=groupOfNames)(cn=" + groupName + ")(member=uid=" + username + ",ou=users," + baseDn + "))"
        val results = ctx.search(baseDn, filter, controls)
        val isMember = results.hasMore()
        ctx.close()
        return mapOf("isMember" to isMember)
    }
}
