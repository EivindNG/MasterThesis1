package server;

import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;

public class KeyDecapsulation {

    public static ECPoint Decapsulate(ECPoint BlindC, BigInteger decryptionKey){

        return BlindC.multiply(decryptionKey).normalize();
    }
}
