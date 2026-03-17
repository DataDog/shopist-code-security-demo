import java.sql.Connection
import java.sql.DriverManager
import java.sql.ResultSet

class ProductQueries {
    private val connectionUrl = "jdbc:postgresql://prod-db:5432/shopist"
    private val dbUser = "app"
    private val dbPass = "apppassword"

    // VULN 1: Kotlin string template SQL injection - product search
    fun searchProducts(searchTerm: String): ResultSet {
        val conn: Connection = DriverManager.getConnection(connectionUrl, dbUser, dbPass)
        val stmt = conn.createStatement()
        val query = "SELECT id, name, description, price FROM products WHERE name LIKE '%$searchTerm%' OR description LIKE '%$searchTerm%'"
        return stmt.executeQuery(query)
    }

    // VULN 2: String concatenation SQL injection - price range query
    fun getProductsByPriceRange(minPrice: String, maxPrice: String): ResultSet {
        val conn: Connection = DriverManager.getConnection(connectionUrl, dbUser, dbPass)
        val stmt = conn.createStatement()
        val query = "SELECT * FROM products WHERE price >= " + minPrice + " AND price <= " + maxPrice + " ORDER BY price ASC"
        return stmt.executeQuery(query)
    }

    // VULN 3: StringBuilder SQL injection - category filter
    fun getProductsByCategory(category: String, sortField: String): ResultSet {
        val conn: Connection = DriverManager.getConnection(connectionUrl, dbUser, dbPass)
        val stmt = conn.createStatement()
        val query = StringBuilder()
            .append("SELECT id, name, price, stock FROM products WHERE category = '")
            .append(category)
            .append("' ORDER BY ")
            .append(sortField)
            .toString()
        return stmt.executeQuery(query)
    }
}
