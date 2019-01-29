package initiator;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class KeyEncapsulation {

    private BigInteger base = BigInteger.valueOf(11);
    private BigInteger i;
    private BigInteger C;
    private BigInteger modulous = BigInteger.valueOf(263);
    private BigInteger k;

    public BigInteger getC() {
        return C;
    }

    public BigInteger getK() {
        return k;
    }

    public KeyEncapsulation(BigInteger ek) throws
            NoSuchAlgorithmException {

        i = new BigInteger(256, SecureRandom.getInstanceStrong()).nextProbablePrime().mod(modulous);
        this.C = base.modPow(i,modulous);
        this.k = ek.modPow(i,modulous);
    }
}
