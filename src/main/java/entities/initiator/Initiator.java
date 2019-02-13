package entities.initiator;

import crypto.EncryptionPk;
import crypto.KeyDerivation;
import entities.AbstractEntitiy;
import org.bouncycastle.math.ec.ECPoint;
import entities.responder.Responder;
import entities.server.Server;
import util.*;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;

public class Initiator extends AbstractEntitiy {


    private KeyPair SkPk;
    private BigInteger nonce;
    private HashMap<AbstractEntitiy, PublicKey> pid; /*Lage Idmaker om til en class. Rather use object class as id? or add object class insted of public key and then later just use object.getPublic*/
    private ECPoint KeyEncryptionKey;
    private SecretKeySpec SharedEncryptionKey;
    private byte[] sid;
    private Server server;
    private ArrayList<Responder> responder;

    public Initiator(Server server, ArrayList<Responder> responder) throws
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
        this.server = server;
        this.responder = responder;
        PublicPrivateKeyGenerator privatepublickey = new PublicPrivateKeyGenerator();
        SkPk = privatepublickey.getPair();
        this.id = IdMaker.getNextId();

        PublicKeyList.getKeyList().put(this, SkPk.getPublic());
        startServer();
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
            IllegalBlockSizeException {

        this.nonce = Nonce.Nonce();
        this.pid = PublicKeyList.getKeyList();
        ByteArrayOutputStream outputStream = stream();

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
            ClassNotFoundException, InvalidAlgorithmParameterException, NoSuchProviderException {

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
    public void EncapAndCreateKey() throws
            NoSuchAlgorithmException,
            IOException,
            IllegalBlockSizeException,
            InvalidKeyException,
            BadPaddingException,
            NoSuchPaddingException,
            SignatureException,
            ClassNotFoundException,
            InvalidAlgorithmParameterException, NoSuchProviderException {


        KeyEncapsulation Encap = new KeyEncapsulation(KeyEncryptionKey);
        byte[] originalKey = KeyDerivation.KDF(BigInteger.valueOf(1), Encap.getK().getAffineXCoord().toBigInteger(), this.sid);
        byte[] Tau = KeyDerivation.KDF(BigInteger.valueOf(2), Encap.getK().getAffineXCoord().toBigInteger(),this.sid);

        /*
        byte[] decodedKey = Base64.getDecoder().decode(originalKey);
        */
        this.SharedEncryptionKey = new SecretKeySpec(originalKey, 0, originalKey.length, "AES");
        System.out.println("Initiator key: " + SharedEncryptionKey.getAlgorithm()+" "+
                SharedEncryptionKey.getEncoded().length+"bytes "+
                Base64.getEncoder().encodeToString(SharedEncryptionKey.getEncoded()));

        for (AbstractEntitiy  entity: pid.keySet()){

            if (entity instanceof Responder){
                Responder responder = (Responder) entity;
                EncryptionPk encryptedData = new EncryptionPk(pid.get(responder), Encap.getC(), this.KeyEncryptionKey, Tau, sid);
                responder.DecryptData(encryptedData,Signing.Sign(SkPk,encryptedData.getCiphertext()),this);
            }
            else {
                continue;
            }
        }
    }
}
