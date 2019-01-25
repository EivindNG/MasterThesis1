package responder;

import java.math.BigInteger;

public class Unblinding {

    private static BigInteger modolus = BigInteger.valueOf(13);

    public static BigInteger Unblind(BigInteger blindk, BigInteger UnblindKey){
        return blindk.modPow(UnblindKey, modolus);
    }
}
