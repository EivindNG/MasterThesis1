package responder;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class Blind {

    private BigInteger t;
    private BigInteger inverset;
    private BigInteger C;
    private BigInteger BlindC;
    private BigInteger UnblindKey;
    private BigInteger modolus = BigInteger.valueOf(13);

    public Blind(BigInteger C) throws NoSuchAlgorithmException {
        this.C = C;
        t = new BigInteger(256, SecureRandom.getInstanceStrong()).mod(modolus);
        BlindC = C.modPow(t,modolus);
        UnblindKey = t.modInverse(modolus);
    }
}
