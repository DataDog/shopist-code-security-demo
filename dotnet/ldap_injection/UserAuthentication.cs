using System.DirectoryServices;

public class UserAuthentication
{
    private const string LdapPath = "LDAP://dc.shopist.internal/DC=shopist,DC=com";

    // VULN 1: String concatenation used to build DirectorySearcher.Filter for LDAP authentication
    public bool AuthenticateUser(string username, string password)
    {
        using var entry = new DirectoryEntry(LdapPath);
        using var searcher = new DirectorySearcher(entry);
        searcher.Filter = "(&(objectClass=user)(sAMAccountName=" + username + ")(userPassword=" + password + "))";
        SearchResult result = searcher.FindOne();
        return result != null;
    }

    // VULN 2: String.Format used to build DirectorySearcher.Filter for employee directory lookup
    public SearchResult LookupEmployee(string department, string employeeName)
    {
        using var entry = new DirectoryEntry(LdapPath);
        using var searcher = new DirectorySearcher(entry);
        searcher.Filter = string.Format("(&(objectClass=person)(department={0})(cn={1}))", department, employeeName);
        return searcher.FindOne();
    }

    // VULN 3: String concatenation used to build DirectorySearcher.Filter for group membership check
    public bool IsUserInGroup(string username, string groupName)
    {
        using var entry = new DirectoryEntry(LdapPath);
        using var searcher = new DirectorySearcher(entry);
        searcher.Filter = "(&(objectClass=user)(sAMAccountName=" + username + ")(memberOf=CN=" + groupName + ",OU=Groups,DC=shopist,DC=com))";
        SearchResult result = searcher.FindOne();
        return result != null;
    }
}
