package server;

import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;

public class KeyDecapsulation {
    
    private static BigInteger modolus = BigInteger.valueOf(263);

    public static ECPoint Decapsulate(ECPoint BlindC, BigInteger decryptionKey){

        return BlindC.multiply(decryptionKey).normalize();
    }
}
