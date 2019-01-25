package crypto;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import java.security.NoSuchAlgorithmException;

public class AsymmetricCryptography {

    public static Cipher AsymmetricCryptography() throws
            NoSuchAlgorithmException,
            NoSuchPaddingException {
        return Cipher.getInstance("RSA");
    }
}
