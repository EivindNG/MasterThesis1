package initiator;

import responder.Responder;
import server.Server;
import util.*;

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
    private String sid;
    private Server server;

    public BigInteger getId() {
        return id;
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

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(nonce.toByteArray());
        for (BigInteger key : pid.keySet()) {
            outputStream.write(key.toByteArray());
        }
        byte AltSammen[] = outputStream.toByteArray();

        server.submitNonce(nonce, pid, Signing.Sign(SkPk, AltSammen), this);

    }
    public void checkSid(BigInteger KeyEncryptionKey, byte[] sign) throws IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {

        ByteArrayOutputStream outputStream2 = new ByteArrayOutputStream( );
        outputStream2.write(nonce.toByteArray());
        for (BigInteger key : pid.keySet()) {
            outputStream2.write(key.toByteArray());
        }
        outputStream2.write(KeyEncryptionKey.toByteArray());
        byte data[] = outputStream2.toByteArray( );

        if (SignVerifyer.Verify(sign, PublicKeyList.getKeyList().get(server.getId()), data)){
            this.KeyEncryptionKey = KeyEncryptionKey;
            sid = sidGenerator.GenerateSid(id, nonce, pid, KeyEncryptionKey);
            System.out.println("Great succsess");
        }
        else{
            throw new IllegalArgumentException();
        }
    }
    public void EncapAndCreateKey(){

    }
}
