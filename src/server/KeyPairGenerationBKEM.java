package server;

import java.math.BigInteger;

public class KeyPairGenerationBKEM {

    private BigInteger base = BigInteger.valueOf(3);
    private BigInteger decryptionKey = BigInteger.valueOf(5);
    private BigInteger encryptionKey;
    private BigInteger modulous = BigInteger.valueOf(11);

    public KeyPairGenerationBKEM(){

        encryptionKey = base.modPow(decryptionKey,modulous);
    }

    public BigInteger getBase() {
        return base;
    }

    public BigInteger getdecryptionKey() {
        return decryptionKey;
    }

    public BigInteger getencryptionKey() {
        return encryptionKey;
    }

    public BigInteger getModulous() {
        return modulous;
    }

    @Override
    public String toString() {
        return "server.KeyPairGenerationBKEM{" +
                "base=" + base +
                ", decryptionKey=" + decryptionKey +
                ", encryptionKey=" + encryptionKey +
                ", modulous=" + modulous +
                '}';
    }
}
