package responder;

import crypto.Constants;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class Blind {


    private ECPoint BlindC;
    private BigInteger UnblindKey;
    private BigInteger modolus = Constants.CURVE_SPEC.getN();
    private BigInteger t = new BigInteger(256, SecureRandom.getInstanceStrong()).mod(modolus);

    public Blind(ECPoint C) throws NoSuchAlgorithmException {

        this.BlindC = C.multiply(t).normalize();

        this.UnblindKey = t.modInverse(modolus);

    }


    public ECPoint getBlindC() {
        return BlindC;
    }

    public BigInteger getUnblindKey() {
        return UnblindKey;
    }
}
