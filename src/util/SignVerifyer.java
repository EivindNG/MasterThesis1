package util;

import java.security.*;

public class SignVerifyer {

    public static boolean Verify(byte[] signature, PublicKey publicKey, byte[] data) throws
            NoSuchAlgorithmException,
            InvalidKeyException,
            SignatureException {

        Signature sign = Signature.getInstance("SHA256withRSA");
        sign.initVerify(publicKey);
        sign.update(data);

        return sign.verify(signature);

    }
}
