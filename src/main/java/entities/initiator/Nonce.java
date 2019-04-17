package entities.initiator;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;


public class Nonce {

    public static BigInteger Nonce() throws
            NoSuchAlgorithmException {

        return new BigInteger(64, new SecureRandom());
    }
}
