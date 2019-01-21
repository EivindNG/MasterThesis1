import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

public class PublicPrivateKeyGenerator {
    private KeyPair pair;

    public KeyPair getPair() {
        return pair;
    }

    public PublicPrivateKeyGenerator() throws NoSuchAlgorithmException {

        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("DSA");
        keyPairGen.initialize(2048);
        KeyPair pair = keyPairGen.generateKeyPair();
    }
}
