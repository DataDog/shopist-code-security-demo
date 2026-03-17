import java.sql.*;

public class ProductQueries {
    private static final String CONNECTION_URL = "jdbc:postgresql://prod-db:5432/shopist";
    private static final String DB_USER = "app";
    private static final String DB_PASS = "apppassword";

    // VULN 1: String concatenation SQL injection - product search
    public ResultSet searchProducts(String searchTerm) throws SQLException {
        Connection conn = DriverManager.getConnection(CONNECTION_URL, DB_USER, DB_PASS);
        Statement stmt = conn.createStatement();
        String query = "SELECT id, name, price, stock FROM products WHERE name LIKE '%" +
            searchTerm + "%' OR description LIKE '%" + searchTerm + "%'";
        return stmt.executeQuery(query);
    }

    // VULN 2: String.format SQL injection - price range filter
    public ResultSet getProductsByPriceRange(String minPrice, String maxPrice) throws SQLException {
        Connection conn = DriverManager.getConnection(CONNECTION_URL, DB_USER, DB_PASS);
        Statement stmt = conn.createStatement();
        String query = String.format(
            "SELECT * FROM products WHERE price BETWEEN %s AND %s ORDER BY price ASC",
            minPrice, maxPrice
        );
        return stmt.executeQuery(query);
    }

    // VULN 3: String concatenation with ORDER BY injection - category filter
    public ResultSet getProductsByCategory(String category, String sortField) throws SQLException {
        Connection conn = DriverManager.getConnection(CONNECTION_URL, DB_USER, DB_PASS);
        Statement stmt = conn.createStatement();
        String query = "SELECT * FROM products WHERE category = '" + category + "' ORDER BY " + sortField;
        return stmt.executeQuery(query);
    }
}
