package responder;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class Blind {

    private BigInteger BlindC;
    private BigInteger UnblindKey;
    private BigInteger modolus = BigInteger.valueOf(263);
    private BigInteger t = new BigInteger(256, SecureRandom.getInstanceStrong()).nextProbablePrime().mod(modolus);


    public Blind(BigInteger C) throws NoSuchAlgorithmException {

        this.BlindC = C.modPow(t,modolus);
        this.UnblindKey = t.modInverse(modolus.add(BigInteger.valueOf(-1)));

    }


    public BigInteger getBlindC() {
        return BlindC;
    }

    public BigInteger getUnblindKey() {
        return UnblindKey;
    }
}
