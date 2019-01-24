package util;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

public class PublicPrivateKeyGenerator {
    private KeyPair pair;

    public KeyPair getPair() {
        return pair;
    }

    public PublicPrivateKeyGenerator() throws NoSuchAlgorithmException {

        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        keyPairGen.initialize(2048);
        pair = keyPairGen.generateKeyPair();
    }
}
