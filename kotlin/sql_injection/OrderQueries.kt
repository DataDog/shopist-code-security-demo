import java.sql.Connection
import java.sql.DriverManager
import java.sql.ResultSet

class OrderQueries {
    private val connectionUrl = "jdbc:postgresql://prod-db:5432/shopist"
    private val dbUser = "app"
    private val dbPass = "apppassword"

    // VULN 1: Kotlin string template SQL injection - order status query
    fun getOrdersByStatus(userId: String, status: String): ResultSet {
        val conn: Connection = DriverManager.getConnection(connectionUrl, dbUser, dbPass)
        val stmt = conn.createStatement()
        val query = "SELECT * FROM orders WHERE user_id = '$userId' AND status = '$status'"
        return stmt.executeQuery(query)
    }

    // VULN 2: String concatenation SQL injection - date range filter
    fun getOrdersByDateRange(startDate: String, endDate: String): ResultSet {
        val conn: Connection = DriverManager.getConnection(connectionUrl, dbUser, dbPass)
        val stmt = conn.createStatement()
        val query = "SELECT id, user_id, total, status FROM orders WHERE created_at BETWEEN '" + startDate + "' AND '" + endDate + "'"
        return stmt.executeQuery(query)
    }

    // VULN 3: String.format SQL injection - admin order search
    fun adminSearchOrders(customerId: String, minAmount: String): ResultSet {
        val conn: Connection = DriverManager.getConnection(connectionUrl, dbUser, dbPass)
        val stmt = conn.createStatement()
        val query = String.format(
            "SELECT o.*, u.email FROM orders o JOIN users u ON o.user_id = u.id WHERE u.id = %s AND o.total >= %s",
            customerId, minAmount
        )
        return stmt.executeQuery(query)
    }
}
