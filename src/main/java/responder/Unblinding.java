package responder;

import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;

public class Unblinding {

    private static BigInteger modolus = BigInteger.valueOf(263);

    public static ECPoint Unblind(ECPoint blindk, BigInteger UnblindKey){

        return blindk.multiply(UnblindKey).normalize();
    }
}
