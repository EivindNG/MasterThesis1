package initiator;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class KeyEncapsulation {

    private BigInteger base = BigInteger.valueOf(3);
    private BigInteger ek;
    private BigInteger i;
    private BigInteger C;
    private BigInteger modulous = BigInteger.valueOf(13);
    private BigInteger k;

    @Override
    public String toString() {
        return "KeyEncapsulation{" +
                "C=" + C +
                ", k=" + k +
                '}';
    }
    public KeyEncapsulation(BigInteger ek) throws NoSuchAlgorithmException {
        this.ek = ek;

        i = new BigInteger(256, SecureRandom.getInstanceStrong()).mod(modulous);
        C = base.modPow(i,modulous);
        k = ek.modPow(i,modulous);
    }
}
