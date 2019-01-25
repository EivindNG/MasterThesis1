package server;

import java.math.BigInteger;

public class KeyDecapsulation {

    private BigInteger BlindC;
    private BigInteger Blindk;
    private BigInteger decryptionKey;
    private static BigInteger modolus = BigInteger.valueOf(13);

    public static BigInteger Decapsulate(BigInteger BlindC, BigInteger decryptionKey){


        return BlindC.modPow(decryptionKey,modolus);
    }
}
