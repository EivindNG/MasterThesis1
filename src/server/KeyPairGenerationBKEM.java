package server;

import java.math.BigInteger;

public class KeyPairGenerationBKEM {

    private BigInteger base = BigInteger.valueOf(3);
    private BigInteger privateKey;
    private BigInteger publicKey;
    private BigInteger modulous = BigInteger.valueOf(11);

    public KeyPairGenerationBKEM(BigInteger privateKey){
        this.privateKey = privateKey;
        publicKey = base.modPow(privateKey,modulous);
    }

    public BigInteger getBase() {
        return base;
    }

    public BigInteger getPrivateKey() {
        return privateKey;
    }

    public BigInteger getPublicKey() {
        return publicKey;
    }

    public BigInteger getModulous() {
        return modulous;
    }

    @Override
    public String toString() {
        return "server.KeyPairGenerationBKEM{" +
                "base=" + base +
                ", privateKey=" + privateKey +
                ", publicKey=" + publicKey +
                ", modulous=" + modulous +
                '}';
    }
}
