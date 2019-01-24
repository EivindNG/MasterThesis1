package initiator;

import crypto.EncryptionPk;
import crypto.KeyDerivation;
import responder.Responder;
import server.Server;
import util.*;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.util.ArrayList;
import java.util.HashMap;

public class Initiator {

    private BigInteger id;
    private KeyPair SkPk;
    private BigInteger nonce;
    private HashMap<BigInteger, PublicKey> pid;
    private BigInteger KeyEncryptionKey;
    private String SharedEncryptionKey;
    private String Tau;
    private String sid;
    private Server server;
    private Responder responder;
    private KeyEncapsulation Encap;
    private byte[] encryptedData;

    public BigInteger getId() {
        return id;
    }

    public Initiator(Server server, Responder responder) throws NoSuchAlgorithmException, IOException, SignatureException, InvalidKeyException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException, ClassNotFoundException {
        this.server = server;
        this.responder = responder;
        PublicPrivateKeyGenerator privatepublickey = new PublicPrivateKeyGenerator();
        SkPk = privatepublickey.getPair();
        id = IdMaker.getNextId();
        PublicKeyList.getKeyList().put(id, SkPk.getPublic());
        startServer();
    }

    public void startServer() throws IOException, NoSuchAlgorithmException, SignatureException, InvalidKeyException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException, ClassNotFoundException {
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
    public void checkSid(BigInteger KeyEncryptionKey, byte[] sign) throws IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException, ClassNotFoundException {

        ByteArrayOutputStream outputStream2 = new ByteArrayOutputStream( );
        outputStream2.write(nonce.toByteArray());
        for (BigInteger key : pid.keySet()) {
            outputStream2.write(key.toByteArray());
        }
        outputStream2.write(KeyEncryptionKey.toByteArray());
        byte data[] = outputStream2.toByteArray( );

        if (SignVerifyer.Verify(sign, PublicKeyList.getKeyList().get(server.getId()), data)){
            this.KeyEncryptionKey = KeyEncryptionKey;
            this.sid = sidGenerator.GenerateSid(id, nonce, pid, KeyEncryptionKey);
            System.out.println("Great succsess, STAGE 1");
            EncapAndCreateKey();
        }
        else{
            throw new IllegalArgumentException();
        }
    }
    public void EncapAndCreateKey() throws NoSuchAlgorithmException, IOException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchPaddingException, SignatureException, ClassNotFoundException {
        Encap = new KeyEncapsulation(KeyEncryptionKey);
        SharedEncryptionKey = KeyDerivation.KDF(BigInteger.valueOf(1), Encap.getK(), this.sid);
        Tau = KeyDerivation.KDF(BigInteger.valueOf(2), Encap.getK(),this.sid);

        for (BigInteger key : pid.keySet()){
            if ((key.compareTo(BigInteger.valueOf(100)))== 1){
                encryptedData = EncryptionPk.Encrypt(pid.get(key), Encap.getC(), this.KeyEncryptionKey, this.Tau, sid);
                responder.DecryptData(encryptedData,Signing.Sign(SkPk,encryptedData),id);
            }
            else {
                continue;
            }
        }

    }
}
