package util;

import entities.AbstractEntitiy;
import org.bouncycastle.math.ec.ECPoint;

import java.io.*;
import java.math.BigInteger;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.HashMap;

public class CombineData implements Serializable {

    byte[] C;
    byte[] KEK;
    byte[] tau;
    byte[] sid;
    byte[] pidIDs;

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

    public byte[] getPidIDs() {
        return pidIDs;
    }

    public CombineData(ECPoint C, ECPoint KEK, byte[] tau, byte[] sid, ArrayList pidIDs) throws IOException {
        this.C = C.getEncoded(false);
        this.KEK = KEK.getEncoded(false);
        this.tau = tau;
        this.sid = sid;


        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        ObjectOutputStream objectStream = new ObjectOutputStream(outputStream);

        objectStream.writeObject(pidIDs);


        this.pidIDs = outputStream.toByteArray();


    }
}
