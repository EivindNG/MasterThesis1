package util;

import crypto.Constants;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;

import java.io.Serializable;

public class CombineData implements Serializable {

    byte[] C;
    byte[] KEK;
    String tau;
    String sid;

    public byte[] getC() {
        return C;
    }

    public byte[] getKEK() {
        return KEK;
    }

    public String getTau() {
        return tau;
    }

    public String getSid() {
        return sid;
    }

    public CombineData(ECPoint C, ECPoint KEK, String tau, String sid){
        this.C = C.getEncoded(false);
        this.KEK = KEK.getEncoded(false);
        this.tau = tau;
        this.sid = sid;
    }
}
