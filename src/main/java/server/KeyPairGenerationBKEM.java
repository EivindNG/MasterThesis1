package server;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;

public class KeyPairGenerationBKEM {

    private BigInteger base = BigInteger.valueOf(11);
    private ECPoint encryptionKey;
    private BigInteger modulous = BigInteger.valueOf(263);
    private BigInteger decryptionKey = new BigInteger(256,SecureRandom.getInstanceStrong()).mod(modulous);

    public KeyPairGenerationBKEM() throws NoSuchAlgorithmException {


        ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256r1");

        encryptionKey = ecSpec.getG().multiply(decryptionKey).normalize();

        /*
        encryptionKey = base.modPow(decryptionKey,modulous);
        */
    }

    public BigInteger getBase() {
        return base;
    }

    public BigInteger getdecryptionKey() {
        return decryptionKey;
    }

    public ECPoint getencryptionKey() {
        return encryptionKey;
    }
}
