package responder;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class Blind {

    ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256r1");
    private ECPoint BlindC;
    private BigInteger UnblindKey;
    private BigInteger modolus = BigInteger.valueOf(263);
    private BigInteger t = new BigInteger(256, SecureRandom.getInstanceStrong()).mod(ecSpec.getCurve().getOrder());


    public Blind(ECPoint C) throws NoSuchAlgorithmException {


        this.BlindC = C.multiply(t).normalize();



        this.UnblindKey = t.modInverse(modolus);

        ECPoint test = BlindC.multiply(UnblindKey).normalize();

    }


    public ECPoint getBlindC() {
        return BlindC;
    }

    public BigInteger getUnblindKey() {
        return UnblindKey;
    }
}
