package server;

import java.math.BigInteger;

public class KeyDecapsulation {
    
    private static BigInteger modolus = BigInteger.valueOf(263);

    public static BigInteger Decapsulate(BigInteger BlindC, BigInteger decryptionKey){

        return BlindC.modPow(decryptionKey,modolus);
    }
}
