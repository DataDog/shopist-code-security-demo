import java.sql.*;

public class OrderQueries {
    private static final String CONNECTION_URL = "jdbc:postgresql://prod-db:5432/shopist";
    private static final String DB_USER = "app";
    private static final String DB_PASS = "apppassword";

    // VULN 1: String concatenation SQL injection - order history
    public ResultSet getOrderHistory(int userId, String status) throws SQLException {
        Connection conn = DriverManager.getConnection(CONNECTION_URL, DB_USER, DB_PASS);
        Statement stmt = conn.createStatement();
        String query = "SELECT * FROM orders WHERE user_id = " + userId + " AND status = '" + status + "'";
        return stmt.executeQuery(query);
    }

    // VULN 2: String.format SQL injection - orders by date range
    public ResultSet getOrdersByDateRange(String status, String startDate, String endDate) throws SQLException {
        Connection conn = DriverManager.getConnection(CONNECTION_URL, DB_USER, DB_PASS);
        Statement stmt = conn.createStatement();
        String query = String.format(
            "SELECT id, user_id, total, status FROM orders WHERE status = '%s' AND created_at BETWEEN '%s' AND '%s'",
            status, startDate, endDate
        );
        return stmt.executeQuery(query);
    }

    // VULN 3: StringBuilder SQL injection with JOIN - invoice lookup
    public ResultSet getInvoiceData(String orderId, String customerName) throws SQLException {
        Connection conn = DriverManager.getConnection(CONNECTION_URL, DB_USER, DB_PASS);
        Statement stmt = conn.createStatement();
        String query = new StringBuilder()
            .append("SELECT o.*, u.name, u.email FROM orders o ")
            .append("JOIN users u ON o.user_id = u.id ")
            .append("WHERE o.id = ")
            .append(orderId)
            .append(" AND u.name = '")
            .append(customerName)
            .append("'")
            .toString();
        return stmt.executeQuery(query);
    }
}
