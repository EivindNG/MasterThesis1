package initiator;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class KeyEncapsulation {

    private BigInteger base = BigInteger.valueOf(11);
    private BigInteger i;
    private ECPoint C;
    private BigInteger modulous = BigInteger.valueOf(263);
    private ECPoint k;

    public ECPoint getC() {
        return C;
    }

    public ECPoint getK() {
        return k;
    }

    public KeyEncapsulation(ECPoint ek) throws
            NoSuchAlgorithmException {

        i = new BigInteger(256, SecureRandom.getInstanceStrong()).mod(modulous);

        ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256r1");
        this.C = ecSpec.getG().multiply(i).normalize();
        this.k = ek.multiply(i).normalize();

        /*
        this.C = base.modPow(i,modulous);
        this.k = ek.modPow(i,modulous);
        */
    }
}
