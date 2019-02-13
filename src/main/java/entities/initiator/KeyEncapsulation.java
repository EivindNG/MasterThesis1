package entities.initiator;

import crypto.Constants;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class KeyEncapsulation {

    private ECPoint C;
    private ECPoint k;

    public ECPoint getC() {
        return C;
    }

    public ECPoint getK() {
        return k;
    }

    public KeyEncapsulation(ECPoint ek) throws
            NoSuchAlgorithmException {

        BigInteger i = new BigInteger(256, SecureRandom.getInstanceStrong()).mod(Constants.CURVE_SPEC.getN());

        this.C = Constants.CURVE_SPEC.getG().multiply(i).normalize();
        this.k = ek.multiply(i).normalize();

        /*
        this.C = base.modPow(i,modulous);
        this.k = ek.modPow(i,modulous);
        */
    }
}
