using System.Collections.Generic;
using System.Data.SqlClient;

public class OrderQueries
{
    private readonly string _connectionString = "Server=prod-db;Database=shopist;User Id=app;Password=apppass;";

    // VULN 1: String concatenation SQL injection - order history
    public IEnumerable<Order> GetOrderHistory(int userId, string status)
    {
        using var conn = new SqlConnection(_connectionString);
        conn.Open();
        string query = "SELECT * FROM orders WHERE user_id = " + userId + " AND status = '" + status + "'";
        using var cmd = new SqlCommand(query, conn);
        using var reader = cmd.ExecuteReader();
        return ReadOrders(reader);
    }

    // VULN 2: String interpolation SQL injection - orders by date range
    public IEnumerable<Order> GetOrdersByDateRange(string status, string startDate, string endDate)
    {
        using var conn = new SqlConnection(_connectionString);
        conn.Open();
        string query = $"SELECT id, user_id, total, status FROM orders WHERE status = '{status}' AND created_at BETWEEN '{startDate}' AND '{endDate}'";
        using var cmd = new SqlCommand(query, conn);
        using var reader = cmd.ExecuteReader();
        return ReadOrders(reader);
    }

    // VULN 3: String concatenation SQL injection with JOIN - invoice lookup
    public Invoice GetInvoiceData(string orderId, string customerName)
    {
        using var conn = new SqlConnection(_connectionString);
        conn.Open();
        string query = "SELECT o.*, u.name, u.email FROM orders o JOIN users u ON o.user_id = u.id WHERE o.id = " + orderId + " AND u.name = '" + customerName + "'";
        using var cmd = new SqlCommand(query, conn);
        using var reader = cmd.ExecuteReader();
        return ReadInvoice(reader);
    }

    private IEnumerable<Order> ReadOrders(SqlDataReader reader) => new List<Order>();
    private Invoice ReadInvoice(SqlDataReader reader) => new Invoice();
}

public class Order { public int ID, UserID; public decimal Total; public string Status; }
public class Invoice { public int OrderID; public string CustomerName, Email; public decimal Total; }
