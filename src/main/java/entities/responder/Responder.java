package entities.responder;

import crypto.Constants;
import crypto.DecryptionSk;
import crypto.EncryptionPk;
import crypto.KeyDerivation;
import entities.AbstractEntitiy;
import entities.initiator.Initiator;
import org.bouncycastle.math.ec.ECPoint;
import entities.server.Server;
import util.*;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.math.BigInteger;
import java.security.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;

public class Responder extends AbstractEntitiy {


    private KeyPair SkPk;
    private CombineData decryptedData;
    private Blind blind;
    private Server server;
    private SecretKeySpec SharedEncryptionKey;
    private ArrayList pidIDs;


    public Responder() throws
            NoSuchAlgorithmException,
            NoSuchProviderException,
            InvalidAlgorithmParameterException {

        PublicPrivateKeyGenerator privatepublickey = new PublicPrivateKeyGenerator();
        this.SkPk = privatepublickey.getPair();
        this.id = IdMaker.getNextId();

        PublicKeyList.getKeyList().put(this,SkPk.getPublic());
    }

    public void DecryptData(EncryptionPk encryptedData, byte[] sign, Initiator initiator, Server server) throws
            NoSuchAlgorithmException,
            InvalidKeyException,
            SignatureException,
            IllegalBlockSizeException,
            ClassNotFoundException,
            BadPaddingException,
            NoSuchPaddingException,
            IOException,
            InvalidAlgorithmParameterException, NoSuchProviderException {
        if (SignVerifyer.Verify(sign,PublicKeyList.getKeyList().get(initiator),encryptedData.getCiphertext())){
            decryptedData = DecryptionSk.Decrypt(encryptedData,SkPk.getPrivate());
            this.server = server;

            System.out.println("Great success, STAGE 2");

            ByteArrayInputStream i = new ByteArrayInputStream(decryptedData.getPidIDs());
            ObjectInputStream inputStream = new ObjectInputStream(i);
            this.pidIDs = (ArrayList) inputStream.readObject();


            BlindAndSign(Constants.CURVE_SPEC.getCurve().decodePoint(decryptedData.getC()),
                    decryptedData.getSid(),Constants.CURVE_SPEC.getCurve().decodePoint(decryptedData.getKEK()));

        }
    }

    public void BlindAndSign(ECPoint C, byte[] sid, ECPoint ek) throws
            NoSuchAlgorithmException,
            IOException,
            SignatureException,
            InvalidKeyException,
            NoSuchProviderException {

        blind = new Blind(C);

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(sid);
        outputStream.write(ek.getEncoded(false));
        outputStream.write(blind.getBlindC().getEncoded(false));

        server.Decapsulate(sid, blind.getBlindC(), Signing.Sign(SkPk,outputStream.toByteArray()),this);
    }

    public void UnblindAndKDF(byte[] sid, ECPoint blindk, byte[] sign, Server server) throws
            IOException,
            NoSuchAlgorithmException,
            InvalidKeyException,
            SignatureException, NoSuchProviderException {

        ByteArrayOutputStream outputStream2 = new ByteArrayOutputStream();
        outputStream2.write(sid);
        outputStream2.write(blindk.getEncoded(false));

        if (SignVerifyer.Verify(sign, PublicKeyList.getKeyList().get(server),outputStream2.toByteArray())){

            ECPoint k = Unblinding.Unblind(blindk,blind.getUnblindKey());

            byte[] originalKey = KeyDerivation.KDF(BigInteger.valueOf(1), k.getAffineXCoord().toBigInteger(), sid);

            this.SharedEncryptionKey = new SecretKeySpec(originalKey, 0, originalKey.length, "AES");

            byte[] tauR = KeyDerivation.KDF(BigInteger.valueOf(2), k.getAffineXCoord().toBigInteger(), sid);

            ValidateKey(tauR);
        }
    }
    public void ValidateKey(byte[] tauR){

        if (Arrays.equals(decryptedData.getTau(),tauR)){
            System.out.println("Great success, STAGE 3. Key is shared" + "\n");
            System.out.println("Responder key: " + SharedEncryptionKey.getAlgorithm()+" "+
                    SharedEncryptionKey.getEncoded().length+"bytes "+
                    Base64.getEncoder().encodeToString(SharedEncryptionKey.getEncoded()));


        }
        else {
            SharedEncryptionKey = null; /*Legge inn slik at det er mulig med flere Encryption keys. En for hver sid, lage en hashmap med keys og corresponding sid.*/
            throw new IllegalArgumentException("Something bad happened");
        }
    }
}

