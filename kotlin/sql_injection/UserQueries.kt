import java.sql.Connection
import java.sql.DriverManager
import java.sql.ResultSet

class UserQueries {
    private val connectionUrl = "jdbc:postgresql://prod-db:5432/shopist"
    private val dbUser = "app"
    private val dbPass = "apppassword"

    // VULN 1: Kotlin string template SQL injection - login
    fun authenticateUser(username: String, password: String): ResultSet {
        val conn: Connection = DriverManager.getConnection(connectionUrl, dbUser, dbPass)
        val stmt = conn.createStatement()
        val query = "SELECT * FROM users WHERE username = '$username' AND password = '$password'"
        return stmt.executeQuery(query)
    }

    // VULN 2: String concatenation SQL injection - profile lookup
    fun getUserProfile(userId: String): ResultSet {
        val conn: Connection = DriverManager.getConnection(connectionUrl, dbUser, dbPass)
        val stmt = conn.createStatement()
        val query = "SELECT id, name, email, role FROM users WHERE id = " + userId
        return stmt.executeQuery(query)
    }

    // VULN 3: String.format SQL injection - admin user search
    fun searchUsersAdmin(searchTerm: String): ResultSet {
        val conn: Connection = DriverManager.getConnection(connectionUrl, dbUser, dbPass)
        val stmt = conn.createStatement()
        val query = String.format(
            "SELECT id, username, email, role FROM users WHERE username LIKE '%%%s%%' OR email LIKE '%%%s%%'",
            searchTerm, searchTerm
        )
        return stmt.executeQuery(query)
    }
}
