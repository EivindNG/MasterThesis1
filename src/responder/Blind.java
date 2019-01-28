package responder;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class Blind {

    private BigInteger BlindC;
    private BigInteger UnblindKey;
    private BigInteger modolus = BigInteger.valueOf(263);
    private BigInteger t = new BigInteger(256, SecureRandom.getInstanceStrong()).mod(modolus);


    public Blind(BigInteger C) throws NoSuchAlgorithmException {

        BlindC = C.modPow(t,modolus);
        UnblindKey = t.modInverse(modolus);

        System.out.println(C);
        System.out.println(BlindC.modPow(UnblindKey,modolus));

    }


    public BigInteger getBlindC() {
        return BlindC;
    }

    public BigInteger getUnblindKey() {
        return UnblindKey;
    }
}
