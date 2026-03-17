import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import java.util.Date;
import java.util.Properties;
import jakarta.mail.*;
import jakarta.mail.internet.*;

public class AuthConfig {

    // VULN 1: Hardcoded JWT secret for token signing
    public String generateAuthToken(String userId, String role) {
        String jwtSecret = "shopist-super-secret-jwt-key-do-not-share-2024";
        return Jwts.builder()
            .setSubject(userId)
            .claim("role", role)
            .setIssuedAt(new Date())
            .setExpiration(new Date(System.currentTimeMillis() + 86400000L))
            .signWith(SignatureAlgorithm.HS256, jwtSecret.getBytes())
            .compact();
    }

    // VULN 2: Hardcoded SMTP credentials for order confirmation emails
    public void sendOrderConfirmationEmail(String toAddress, String orderSummary) throws MessagingException {
        String smtpUser = "shopist-noreply@shopist.com";
        String smtpPassword = "Sh0pist!Mail#2024";
        Properties props = new Properties();
        props.put("mail.smtp.host", "smtp.sendgrid.net");
        props.put("mail.smtp.port", "587");
        props.put("mail.smtp.auth", "true");
        props.put("mail.smtp.starttls.enable", "true");
        Session session = Session.getInstance(props, new Authenticator() {
            protected PasswordAuthentication getPasswordAuthentication() {
                return new PasswordAuthentication(smtpUser, smtpPassword);
            }
        });
        Message message = new MimeMessage(session);
        message.setFrom(new InternetAddress(smtpUser));
        message.setRecipients(Message.RecipientType.TO, InternetAddress.parse(toAddress));
        message.setSubject("Your Shopist Order Confirmation");
        message.setText(orderSummary);
        Transport.send(message);
    }

    // VULN 3: Hardcoded admin credentials in login check
    public boolean isAdminUser(String username, String password) {
        String adminUsername = "shopist_admin";
        String adminPassword = "Adm1n@Shopist#Prod";
        return adminUsername.equals(username) && adminPassword.equals(password);
    }
}
