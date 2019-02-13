package entities.responder;

import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;

public class Unblinding {

    public static ECPoint Unblind(ECPoint blindk, BigInteger UnblindKey){

        return blindk.multiply(UnblindKey).normalize();
    }
}
