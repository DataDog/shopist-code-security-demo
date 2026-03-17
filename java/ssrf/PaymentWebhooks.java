import jakarta.servlet.http.*;
import java.io.*;
import java.net.*;
import java.nio.file.*;

public class PaymentWebhooks extends HttpServlet {

    // VULN 1: User-controlled webhook URL fetched via HttpURLConnection
    public String deliverPaymentWebhook(HttpServletRequest req, String payload) throws IOException {
        String webhookUrl = req.getParameter("webhook_url");
        URL url = new URL(webhookUrl);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setDoOutput(true);
        conn.getOutputStream().write(payload.getBytes());
        return new String(conn.getInputStream().readAllBytes());
    }

    // VULN 2: User-supplied product image URL fetched and saved to disk
    public void saveProductImageFromUrl(HttpServletRequest req) throws IOException {
        String imageUrl = req.getParameter("image_url");
        String productId = req.getParameter("product_id");
        URL url = new URL(imageUrl);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        byte[] imageBytes = conn.getInputStream().readAllBytes();
        Files.write(Paths.get("/var/www/shopist/images/products/" + productId + ".jpg"), imageBytes);
    }

    // VULN 3: User-controlled carrier URL for shipment tracking status
    public String fetchShippingStatus(HttpServletRequest req) throws IOException {
        String carrierUrl = req.getParameter("carrier_tracking_url");
        String trackingId  = req.getParameter("tracking_id");
        URL url = new URL(carrierUrl + "/track/" + trackingId);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("GET");
        return new String(conn.getInputStream().readAllBytes());
    }
}
