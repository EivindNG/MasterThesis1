package initiator;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;


public class Nonce {
    private BigInteger nonce;

    @Override
    public String toString() {
        return "Nonce{" +
                ", nonce='" + nonce + '\'' +
                '}';
    }

    public Nonce() throws NoSuchAlgorithmException {


        nonce = new BigInteger(256, SecureRandom.getInstanceStrong());
    }
}
