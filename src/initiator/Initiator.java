package initiator;

import responder.Responder;
import server.Server;
import util.IdMaker;
import util.PublicKeyList;
import util.PublicPrivateKeyGenerator;
import util.Signing;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.util.ArrayList;
import java.util.HashMap;

public class Initiator {

    private BigInteger id;
    private KeyPair SkPk;
    private KeyEncapsulation result;
    private BigInteger nonce;
    private HashMap<BigInteger, PublicKey> pid;
    private BigInteger KeyEncryptionKey;
    private BigInteger EncryptionKey;
    private BigInteger SharedEncryptionKey;
    private BigInteger Tau;
    private BigInteger sid;
    private Server server;

    public BigInteger getId() {
        return id;
    }

    @Override
    public String toString() {
        return "Initiator{" +
                "result=" + result +
                ", nonce=" + nonce +
                '}';
    }

    public Initiator(Server server) throws NoSuchAlgorithmException, IOException, SignatureException, InvalidKeyException {
        this.server = server;
        PublicPrivateKeyGenerator privatepublickey = new PublicPrivateKeyGenerator();
        SkPk = privatepublickey.getPair();
        id = IdMaker.getNextId();
        PublicKeyList.getKeyList().put(id, SkPk.getPublic());
        startServer();
    }

    public void startServer() throws IOException, NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        nonce = Nonce.Nonce();
        pid = PublicKeyList.getKeyList();

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
        outputStream.write(nonce.toByteArray());
        for (BigInteger key : pid.keySet()) {
            outputStream.write(key.toByteArray());
        }
        byte AltSammen[] = outputStream.toByteArray( );

        server.submitNonce(nonce, pid, Signing.Sign(SkPk,AltSammen),this);
    }
}
