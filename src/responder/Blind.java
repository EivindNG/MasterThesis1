package responder;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class Blind {

    private BigInteger t;
    private BigInteger BlindC;

    public BigInteger getBlindC() {
        return BlindC;
    }

    public BigInteger getUnblindKey() {
        return UnblindKey;
    }

    private BigInteger UnblindKey;
    private BigInteger modolus = BigInteger.valueOf(13);

    public Blind(BigInteger C) throws NoSuchAlgorithmException {
        t = new BigInteger(256, SecureRandom.getInstanceStrong()).mod(modolus);
        BlindC = C.modPow(t,modolus);
        UnblindKey = t.modInverse(modolus);
    }
}
