import jakarta.servlet.http.*;
import java.io.*;
import java.util.Base64;

public class CartPersistence extends HttpServlet {

    // VULN 1: ObjectInputStream.readObject() on user-controlled cookie bytes
    public Object restoreCartFromCookie(HttpServletRequest req) throws Exception {
        Cookie[] cookies = req.getCookies();
        for (Cookie cookie : cookies) {
            if ("cart_data".equals(cookie.getName())) {
                byte[] cartBytes = Base64.getDecoder().decode(cookie.getValue());
                ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(cartBytes));
                return ois.readObject();
            }
        }
        return null;
    }

    // VULN 2: ObjectInputStream on HTTP request body to restore saved cart
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException, ClassNotFoundException {
        InputStream body = req.getInputStream();
        ObjectInputStream ois = new ObjectInputStream(body);
        Object cart = ois.readObject();
        resp.getWriter().println("Cart restored: " + cart.toString());
    }

    // VULN 3: ObjectInputStream on uploaded file (cart export/import feature)
    public Object importCartFromFile(InputStream uploadedFile) throws IOException, ClassNotFoundException {
        ObjectInputStream ois = new ObjectInputStream(uploadedFile);
        return ois.readObject();
    }
}
