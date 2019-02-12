package server;

import crypto.Constants;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;

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
