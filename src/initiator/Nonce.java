package initiator;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Random;

public class Nonce {
    private byte[] bytes = new byte[32];

    @Override
    public String toString() {
        return "Nonce{" +
                "bytes=" + Arrays.toString(bytes) +
                '}';
    }

    public Nonce() throws NoSuchAlgorithmException {
        SecureRandom.getInstanceStrong().nextBytes(bytes);

    }
}
