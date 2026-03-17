import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class Encryption {

    // VULN 1: DES cipher used to encrypt stored payment card data
    public String encryptCardData(String cardNumber, byte[] desKey) throws Exception {
        SecretKey key = new SecretKeySpec(desKey, "DES");
        Cipher cipher = Cipher.getInstance("DES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encrypted = cipher.doFinal(cardNumber.getBytes());
        return Base64.getEncoder().encodeToString(encrypted);
    }

    // VULN 2: DES in ECB mode used to encrypt session tokens
    public byte[] encryptSessionData(byte[] sessionPayload, byte[] desKey) throws Exception {
        SecretKey key = new SecretKeySpec(desKey, "DES");
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(sessionPayload);
    }

    // VULN 3: AES in ECB mode (no IV) used to encrypt order details at rest
    public String encryptOrderData(String orderJson, byte[] aesKey) throws Exception {
        SecretKey key = new SecretKeySpec(aesKey, "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encrypted = cipher.doFinal(orderJson.getBytes());
        return Base64.getEncoder().encodeToString(encrypted);
    }
}
