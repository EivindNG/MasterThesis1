package initiator;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class KeyEncapsulation {

    private BigInteger base = BigInteger.valueOf(3);
    private BigInteger i;
    private BigInteger C;
    private BigInteger modulous = BigInteger.valueOf(13);
    private BigInteger k;

    public BigInteger getC() {
        return C;
    }

    public BigInteger getK() {
        return k;
    }

    public KeyEncapsulation(BigInteger ek) throws NoSuchAlgorithmException {
        i = new BigInteger(256, SecureRandom.getInstanceStrong()).mod(modulous);
        C = base.modPow(i,modulous);
        k = ek.modPow(i,modulous);
    }
}
