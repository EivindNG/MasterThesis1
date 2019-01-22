package initiator;

import responder.Responder;
import util.IdMaker;
import util.PublicKeyList;
import util.PublicPrivateKeyGenerator;

import java.math.BigInteger;

import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;

public class Initiator {

    private BigInteger id;
    private KeyPair SkPk;
    private KeyEncapsulation result;
    private Nonce nonce;
    private ArrayList<Integer> pid;
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
        PublicPrivateKeyGenerator privatepublickey = new PublicPrivateKeyGenerator();
        SkPk = privatepublickey.getPair();
        id = IdMaker.getNextId();
        PublicKeyList.getKeyList().put(id,SkPk.getPublic());


        nonce = new Nonce();

    }
}
