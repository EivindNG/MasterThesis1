package initiator;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class KeyEncapsulation {
    private BigInteger ek;
    private BigInteger base;
    private BigInteger i;

    public KeyEncapsulation(BigInteger ek, BigInteger base) throws NoSuchAlgorithmException {
        this.ek = ek;
        this.base = base;

        i = new BigInteger(256, SecureRandom.getInstanceStrong());

    }
}
