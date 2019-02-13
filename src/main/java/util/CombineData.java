package util;

import org.bouncycastle.math.ec.ECPoint;

import java.io.Serializable;

public class CombineData implements Serializable {

    byte[] C;
    byte[] KEK;
    byte[] tau;
    byte[] sid;

    public byte[] getC() {
        return C;
    }

    public byte[] getKEK() {
        return KEK;
    }

    public byte[] getTau() {
        return tau;
    }

    public byte[] getSid() {
        return sid;
    }

    public CombineData(ECPoint C, ECPoint KEK, byte[] tau, byte[] sid){
        this.C = C.getEncoded(false);
        this.KEK = KEK.getEncoded(false);
        this.tau = tau;
        this.sid = sid;
    }
}
