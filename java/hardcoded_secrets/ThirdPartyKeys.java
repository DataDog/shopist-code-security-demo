import com.sendgrid.SendGrid;
import com.sendgrid.Request;
import com.sendgrid.Method;
import com.sendgrid.helpers.mail.Mail;
import com.sendgrid.helpers.mail.objects.Email;
import com.sendgrid.helpers.mail.objects.Content;
import com.twilio.Twilio;
import com.twilio.rest.api.v2010.account.Message;
import com.twilio.type.PhoneNumber;
import java.net.HttpURLConnection;
import java.net.URL;
import java.io.IOException;

public class ThirdPartyKeys {

    // VULN 1: Hardcoded SendGrid API key for transactional emails
    public void sendShippingNotification(String toEmail, String trackingNumber) throws IOException {
        String sendGridApiKey = "SG.aBcDeFgHiJkLmNoPqRsTuV.WxYzAbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfG";
        SendGrid sg = new SendGrid(sendGridApiKey);
        Mail mail = new Mail(
            new Email("shipping@shopist.com"),
            "Your Shopist order has shipped!",
            new Email(toEmail),
            new Content("text/plain", "Tracking number: " + trackingNumber)
        );
        Request request = new Request();
        request.setMethod(Method.POST);
        request.setEndpoint("mail/send");
        request.setBody(mail.build());
        sg.api(request);
    }

    // VULN 2: Hardcoded Google Maps API key for store locator and delivery estimation
    public String getDeliveryEstimate(String originAddress, String destinationAddress) throws IOException {
        String googleMapsApiKey = "AIzaSyD-9tSrke72I4lD1tU8WmPoKQmLz4mVJHk";
        String urlStr = "https://maps.googleapis.com/maps/api/distancematrix/json"
            + "?origins=" + originAddress.replace(" ", "+")
            + "&destinations=" + destinationAddress.replace(" ", "+")
            + "&key=" + googleMapsApiKey;
        URL url = new URL(urlStr);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("GET");
        return new String(conn.getInputStream().readAllBytes());
    }

    // VULN 3: Hardcoded Twilio account SID and auth token for SMS order alerts
    public void sendOrderSmsAlert(String toPhone, String orderStatus) {
        String twilioAccountSid = "ACa1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6";
        String twilioAuthToken  = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6";
        Twilio.init(twilioAccountSid, twilioAuthToken);
        Message.creator(
            new PhoneNumber(toPhone),
            new PhoneNumber("+15005550006"),
            "Shopist order update: " + orderStatus
        ).create();
    }
}
