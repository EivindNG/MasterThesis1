package responder;

import java.math.BigInteger;

public class Unblind {

    private BigInteger k;
    private BigInteger blindk;
    private BigInteger modolus;
    private BigInteger UnblindKey;

    public Unblind(BigInteger blindk, BigInteger UnblindKey){
        this.blindk = blindk;
        this.UnblindKey = UnblindKey;

        k = blindk.modPow(UnblindKey, modolus);
    }
}
