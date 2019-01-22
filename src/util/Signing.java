package util;

import java.math.BigInteger;
import java.security.*;
import java.util.ArrayList;

public class Signing {

    public static byte [] Signing(KeyPair pair, byte[] Stufftosign) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {

        Signature sign = Signature.getInstance("SHA256withDSA");
        sign.initSign(pair.getPrivate());
        sign.update(Stufftosign);

        return sign.sign();
    }
}

