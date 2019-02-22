package entities.initiator;

import crypto.EncryptionPk;
import crypto.KeyDerivation;
import entities.AbstractEntitiy;
import org.bouncycastle.math.ec.ECPoint;
import entities.responder.Responder;
import entities.server.Server;
import util.*;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;

public class Initiator extends AbstractEntitiy {


    private KeyPair SkPk;
    private BigInteger nonce;
    private HashMap<AbstractEntitiy, PublicKey> pid;
    private ECPoint KeyEncryptionKey;
    private SecretKeySpec SharedEncryptionKey;
    private IvParameterSpec iv;
    private byte[] sid;
    private Server server;
    private ArrayList pidIDs = new ArrayList();


    public Initiator() throws
            NoSuchAlgorithmException,
            IOException,
            SignatureException,
            InvalidKeyException,
            NoSuchPaddingException,
            BadPaddingException,
            IllegalBlockSizeException,
            ClassNotFoundException,
            InvalidAlgorithmParameterException,
            NoSuchProviderException {

        PublicPrivateKeyGenerator privatepublickey = new PublicPrivateKeyGenerator();
        SkPk = privatepublickey.getPair();
        this.id = IdMaker.getNextId();

        PublicKeyList.getKeyList().put(this, SkPk.getPublic());

    }

    public void startServer() throws
            IOException,
            NoSuchAlgorithmException,
            SignatureException,
            InvalidKeyException,
            NoSuchProviderException,
            ClassNotFoundException,
            NoSuchPaddingException,
            BadPaddingException,
            InvalidAlgorithmParameterException,
            IllegalBlockSizeException, InvalidKeySpecException {

        this.nonce = Nonce.Nonce();
        this.pid = PublicKeyList.getKeyList();
        ByteArrayOutputStream outputStream = stream();

        for (AbstractEntitiy entity: pid.keySet()) {

            this.pidIDs.add(entity.getId());
        }

        for (AbstractEntitiy  entity: pid.keySet()){

            if (entity instanceof Server) {
                this.server = (Server) entity;
            }
        }

        server.submitNonce(nonce, this.pid, Signing.Sign(SkPk, outputStream.toByteArray()), this);
    }

    public ByteArrayOutputStream stream() throws IOException {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(nonce.toByteArray());
        for (AbstractEntitiy entity: pid.keySet()) {
            outputStream.write(entity.getId().toByteArray());
        }
        return outputStream;
    }

    public void checkSid(ECPoint KeyEncryptionKey, byte[] sign, Server server) throws
            IOException,
            NoSuchAlgorithmException,
            InvalidKeyException,
            SignatureException,
            NoSuchPaddingException,
            BadPaddingException,
            IllegalBlockSizeException,
            ClassNotFoundException, InvalidAlgorithmParameterException, NoSuchProviderException, InvalidKeySpecException {

        ByteArrayOutputStream outputStream2 = stream();

        outputStream2.write(KeyEncryptionKey.getEncoded(false));
        byte data[] = outputStream2.toByteArray( );

        if (SignVerifyer.Verify(sign, PublicKeyList.getKeyList().get(server), data)){
            this.KeyEncryptionKey = KeyEncryptionKey;
            this.sid = sidGenerator.GenerateSid(id, nonce, pid, KeyEncryptionKey);
            System.out.println("Great succsess, STAGE 1");
            EncapAndCreateKey();
        }
        else{
            throw new IllegalArgumentException();
        }
    }

    public SecretKeySpec getSharedEncryptionKey() {
        return SharedEncryptionKey;
    }

    public IvParameterSpec getIv() {
        return iv;
    }

    public void EncapAndCreateKey() throws
            NoSuchAlgorithmException,
            IOException,
            IllegalBlockSizeException,
            InvalidKeyException,
            BadPaddingException,
            NoSuchPaddingException,
            SignatureException,
            ClassNotFoundException,
            InvalidAlgorithmParameterException, NoSuchProviderException, InvalidKeySpecException {


        KeyEncapsulation Encap = new KeyEncapsulation(KeyEncryptionKey);
        byte[] originalKey = KeyDerivation.KDF(BigInteger.valueOf(1), Encap.getK().getAffineXCoord().toBigInteger(), this.sid);
        byte[] Tau = KeyDerivation.KDF(BigInteger.valueOf(2), Encap.getK().getAffineXCoord().toBigInteger(),this.sid);

        /*
        byte[] decodedKey = Base64.getDecoder().decode(originalKey);
        */
        byte[] SEK = Arrays.copyOfRange(originalKey, 0, 32);
        byte[] IV = Arrays.copyOfRange(originalKey, 32, 48);

        this.SharedEncryptionKey = new SecretKeySpec(SEK, 0, SEK.length, "AES");
        this.iv = new IvParameterSpec(IV);
        /*
        this.iv = new IvParameterSpec(IV);
        */

        System.out.println("Initiator key: " + SharedEncryptionKey.getAlgorithm()+" "+
                SharedEncryptionKey.getEncoded().length + "bytes "+
                Base64.getEncoder().encodeToString(SharedEncryptionKey.getEncoded())+iv +"\n");


        for (AbstractEntitiy  entity: pid.keySet()){

            if (entity instanceof Responder){
                Responder responder = (Responder) entity;
                EncryptionPk encryptedData = new EncryptionPk(pid.get(responder), Encap.getC(), this.KeyEncryptionKey, Tau, sid, pidIDs);
                responder.DecryptData(encryptedData,Signing.Sign(SkPk,encryptedData.getCiphertext()),this, server);
            }
            else {
                continue;
            }
        }
    }
}
