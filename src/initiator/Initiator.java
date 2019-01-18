package initiator;

import responder.Responder;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;

public class Initiator {

    private KeyEncapsulation result;
    private Nonce nonce;
    private ArrayList<Responder> pid;
    private BigInteger KeyEncryptionKey;
    private BigInteger EncryptionKey;
    private BigInteger SharedEncryptionKey;
    private BigInteger Tau;
    private BigInteger sid;

    @Override
    public String toString() {
        return "Initiator{" +
                "result=" + result +
                ", nonce=" + nonce +
                '}';
    }

    public Initiator() throws NoSuchAlgorithmException {
        nonce = new Nonce();

    }
}
