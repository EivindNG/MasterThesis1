package util;

import java.security.*;

public class Signing {

    public static byte [] Sign(KeyPair pair, byte[] Stufftosign) throws
            NoSuchAlgorithmException,
            InvalidKeyException,
            SignatureException,
            NoSuchProviderException {

        Signature sign = Signature.getInstance("SHA256withECDSA","BC");
        sign.initSign(pair.getPrivate());
        sign.update(Stufftosign);

        return sign.sign();
    }
}

