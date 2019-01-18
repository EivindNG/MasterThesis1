package server;

import java.math.BigInteger;

public class KeyDecapsulation {

    private BigInteger BlindC;
    private BigInteger Blindk;
    private BigInteger decryptionKey;
    private BigInteger modolus = BigInteger.valueOf(13);

    public KeyDecapsulation(BigInteger BlindC, BigInteger decryptionKey){
        this.BlindC = BlindC;

        Blindk = BlindC.modPow(decryptionKey,modolus);
    }
}
