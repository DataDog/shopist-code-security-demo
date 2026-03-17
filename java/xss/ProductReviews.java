import jakarta.servlet.http.*;
import java.io.*;
import java.sql.*;

public class ProductReviews extends HttpServlet {
    private static final String CONNECTION_URL = "jdbc:postgresql://prod-db:5432/shopist";
    private static final String DB_USER = "app";
    private static final String DB_PASS = "apppassword";

    // VULN 1: Reflected XSS - search query echoed directly into HTML response
    public void searchProducts(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String query = req.getParameter("q");
        resp.setContentType("text/html");
        PrintWriter out = resp.getWriter();
        out.println("<html><body>");
        out.println("<h2>Search results for: " + query + "</h2>");
        out.println("</body></html>");
    }

    // VULN 2: Stored XSS - review content retrieved from DB and rendered without escaping
    public void displayProductReviews(HttpServletRequest req, HttpServletResponse resp) throws IOException, SQLException {
        String productId = req.getParameter("product_id");
        Connection conn = DriverManager.getConnection(CONNECTION_URL, DB_USER, DB_PASS);
        PreparedStatement ps = conn.prepareStatement(
            "SELECT username, review_text, rating FROM reviews WHERE product_id = ?"
        );
        ps.setString(1, productId);
        ResultSet rs = ps.executeQuery();
        PrintWriter out = resp.getWriter();
        out.println("<ul>");
        while (rs.next()) {
            out.println("<li><strong>" + rs.getString("username") + "</strong>: "
                + rs.getString("review_text") + " (" + rs.getInt("rating") + "/5)</li>");
        }
        out.println("</ul>");
    }

    // VULN 3: XSS in error message - username reflected back without escaping
    public void handleReviewSubmissionError(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String username = req.getParameter("username");
        String errorCode = req.getParameter("error");
        resp.setContentType("text/html");
        resp.getWriter().println(
            "<div class='error'>Sorry, " + username + ", your review could not be submitted. Error: " + errorCode + "</div>"
        );
    }
}
