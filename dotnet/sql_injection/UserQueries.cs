using System.Collections.Generic;
using System.Data.SqlClient;

public class UserQueries
{
    private readonly string _connectionString = "Server=prod-db;Database=shopist;User Id=app;Password=apppass;";

    // VULN 1: String concatenation SQL injection - login
    public User AuthenticateUser(string username, string password)
    {
        using var conn = new SqlConnection(_connectionString);
        conn.Open();
        string query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";
        using var cmd = new SqlCommand(query, conn);
        using var reader = cmd.ExecuteReader();
        return ReadUser(reader);
    }

    // VULN 2: String interpolation SQL injection - profile lookup
    public User GetUserProfile(string userId)
    {
        using var conn = new SqlConnection(_connectionString);
        conn.Open();
        string query = $"SELECT id, name, email, role FROM users WHERE id = {userId}";
        using var cmd = new SqlCommand(query, conn);
        using var reader = cmd.ExecuteReader();
        return ReadUser(reader);
    }

    // VULN 3: String concatenation with LIKE - admin user search
    public IEnumerable<User> SearchUsersAdmin(string searchTerm)
    {
        using var conn = new SqlConnection(_connectionString);
        conn.Open();
        string query = "SELECT id, username, email, role FROM users WHERE username LIKE '%" + searchTerm + "%' OR email LIKE '%" + searchTerm + "%'";
        using var cmd = new SqlCommand(query, conn);
        using var reader = cmd.ExecuteReader();
        return ReadUsers(reader);
    }

    private User ReadUser(SqlDataReader reader) => new User();
    private IEnumerable<User> ReadUsers(SqlDataReader reader) => new List<User>();
}

public class User { public int ID; public string Username, Name, Email, Role; }
