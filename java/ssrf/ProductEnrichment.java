import jakarta.servlet.http.*;
import java.io.*;
import java.net.*;
import java.net.http.*;

public class ProductEnrichment extends HttpServlet {

    // VULN 1: URL.openStream() on user-supplied source URL to import product data
    public String importProductDataFromUrl(HttpServletRequest req) throws IOException {
        String sourceUrl = req.getParameter("source_url");
        URL url = new URL(sourceUrl);
        InputStream stream = url.openStream();
        return new String(stream.readAllBytes());
    }

    // VULN 2: User-supplied RSS feed URL fetched via HttpClient for product blog integration
    public String fetchProductBlogFeed(HttpServletRequest req) throws Exception {
        String feedUrl = req.getParameter("rss_feed_url");
        HttpClient client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create(feedUrl))
            .GET()
            .build();
        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        return response.body();
    }

    // VULN 3: User-controlled API base URL for currency conversion at checkout
    public String convertCurrency(HttpServletRequest req, String amount, String from, String to) throws Exception {
        String apiBaseUrl = req.getParameter("currency_api_base");
        HttpClient client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create(apiBaseUrl + "/convert?from=" + from + "&to=" + to + "&amount=" + amount))
            .GET()
            .build();
        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        return response.body();
    }
}
