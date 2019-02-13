package entities.server;

import crypto.Constants;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class KeyPairGenerationBKEM {

    private ECPoint encryptionKey;
    private BigInteger decryptionKey = new BigInteger(256,SecureRandom.getInstanceStrong()).mod(Constants.CURVE_SPEC.getN());

    public KeyPairGenerationBKEM() throws NoSuchAlgorithmException {

        encryptionKey = Constants.CURVE_SPEC.getG().multiply(decryptionKey).normalize();

        /*
        encryptionKey = base.modPow(decryptionKey,modulous);
        */
    }

    public BigInteger getdecryptionKey() {
        return decryptionKey;
    }

    public ECPoint getencryptionKey() {
        return encryptionKey;
    }
}
