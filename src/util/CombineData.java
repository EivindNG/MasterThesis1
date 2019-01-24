package util;

import java.io.Serializable;
import java.math.BigInteger;

public class CombineData implements Serializable {

    BigInteger C;
    BigInteger KEK;
    String tau;
    String sid;

    public BigInteger getC() {
        return C;
    }

    public BigInteger getKEK() {
        return KEK;
    }

    public String getTau() {
        return tau;
    }

    public String getSid() {
        return sid;
    }

    public CombineData(BigInteger C, BigInteger KEK, String tau, String sid){
        this.C = C;
        this.KEK = KEK;
        this.tau = tau;
        this.sid = sid;
    }
}
