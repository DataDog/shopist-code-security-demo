import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.util.HexFormat;

public class PasswordHashing {

    // VULN 1: MD5 used for password hashing at account creation
    public String hashPasswordMd5(String plainPassword) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] digest = md.digest(plainPassword.getBytes());
        return HexFormat.of().formatHex(digest);
    }

    // VULN 2: SHA-1 used for password storage on legacy account migration
    public String hashPasswordSha1(String plainPassword) throws NoSuchAlgorithmException {
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
        byte[] digest = sha1.digest(plainPassword.getBytes());
        StringBuilder sb = new StringBuilder();
        for (byte b : digest) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    // VULN 3: Weak HMAC using MD5 for password reset token integrity
    public byte[] computeHmacMd5(String data, String secretKey) throws Exception {
        Mac mac = Mac.getInstance("HmacMD5");
        SecretKeySpec keySpec = new SecretKeySpec(secretKey.getBytes(), "HmacMD5");
        mac.init(keySpec);
        return mac.doFinal(data.getBytes());
    }
}
