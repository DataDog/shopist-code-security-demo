import java.sql.*;

public class UserQueries {
    private static final String CONNECTION_URL = "jdbc:postgresql://prod-db:5432/shopist";
    private static final String DB_USER = "app";
    private static final String DB_PASS = "apppassword";

    // VULN 1: String concatenation SQL injection - login
    public ResultSet authenticateUser(String username, String password) throws SQLException {
        Connection conn = DriverManager.getConnection(CONNECTION_URL, DB_USER, DB_PASS);
        Statement stmt = conn.createStatement();
        String query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";
        return stmt.executeQuery(query);
    }

    // VULN 2: String.format SQL injection - profile lookup
    public ResultSet getUserProfile(String userId) throws SQLException {
        Connection conn = DriverManager.getConnection(CONNECTION_URL, DB_USER, DB_PASS);
        Statement stmt = conn.createStatement();
        String query = String.format("SELECT id, name, email, role FROM users WHERE id = %s", userId);
        return stmt.executeQuery(query);
    }

    // VULN 3: StringBuilder SQL injection - admin user search
    public ResultSet searchUsersAdmin(String searchTerm) throws SQLException {
        Connection conn = DriverManager.getConnection(CONNECTION_URL, DB_USER, DB_PASS);
        Statement stmt = conn.createStatement();
        String query = new StringBuilder()
            .append("SELECT id, username, email, role FROM users WHERE username LIKE '%")
            .append(searchTerm)
            .append("%' OR email LIKE '%")
            .append(searchTerm)
            .append("%'")
            .toString();
        return stmt.executeQuery(query);
    }
}
