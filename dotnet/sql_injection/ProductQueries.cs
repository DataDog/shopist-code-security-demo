using System.Collections.Generic;
using System.Data.SqlClient;

public class ProductQueries
{
    private readonly string _connectionString = "Server=prod-db;Database=shopist;User Id=app;Password=apppass;";

    // VULN 1: String concatenation SQL injection - product search
    public IEnumerable<Product> SearchProducts(string searchTerm)
    {
        using var conn = new SqlConnection(_connectionString);
        conn.Open();
        string query = "SELECT id, name, price, stock FROM products WHERE name LIKE '%" + searchTerm + "%' OR description LIKE '%" + searchTerm + "%'";
        using var cmd = new SqlCommand(query, conn);
        using var reader = cmd.ExecuteReader();
        return ReadProducts(reader);
    }

    // VULN 2: String interpolation SQL injection - price range filter
    public IEnumerable<Product> GetProductsByPriceRange(string minPrice, string maxPrice)
    {
        using var conn = new SqlConnection(_connectionString);
        conn.Open();
        string query = $"SELECT * FROM products WHERE price BETWEEN {minPrice} AND {maxPrice} ORDER BY price ASC";
        using var cmd = new SqlCommand(query, conn);
        using var reader = cmd.ExecuteReader();
        return ReadProducts(reader);
    }

    // VULN 3: String concatenation with ORDER BY injection - category filter
    public IEnumerable<Product> GetProductsByCategory(string category, string sortField)
    {
        using var conn = new SqlConnection(_connectionString);
        conn.Open();
        string query = "SELECT * FROM products WHERE category = '" + category + "' ORDER BY " + sortField;
        using var cmd = new SqlCommand(query, conn);
        using var reader = cmd.ExecuteReader();
        return ReadProducts(reader);
    }

    private IEnumerable<Product> ReadProducts(SqlDataReader reader) => new List<Product>();
}

public class Product { public int ID, Stock; public string Name, Category; public decimal Price; }
