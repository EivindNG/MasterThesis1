package util;

import crypto.Constants;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;

import java.security.*;
import java.security.spec.ECGenParameterSpec;

public class PublicPrivateKeyGenerator {

    private KeyPair pair;

    public PublicPrivateKeyGenerator() throws
            NoSuchAlgorithmException,
            NoSuchProviderException,
            InvalidAlgorithmParameterException {

        KeyPairGenerator g = KeyPairGenerator.getInstance("EC", "BC");
        g.initialize(Constants.CURVE_SPEC, new SecureRandom());
        this.pair = g.generateKeyPair();
    }

    public KeyPair getPair() {
        return pair;
    }
}
