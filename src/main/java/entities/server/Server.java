package entities.server;

import entities.AbstractEntitiy;
import entities.initiator.Initiator;
import entities.responder.Responder;
import org.bouncycastle.math.ec.ECPoint;
import util.*;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;

public class Server extends AbstractEntitiy {


    private KeyPair SkPk;
    private KeyPairGenerationBKEM ekdk;
    private byte[] sid;
    private HashMap<AbstractEntitiy, PublicKey> pid;

    public Server() throws

            NoSuchAlgorithmException,
            NoSuchProviderException,
            InvalidAlgorithmParameterException {

        PublicPrivateKeyGenerator privatepublickey = new PublicPrivateKeyGenerator();
        this.SkPk = privatepublickey.getPair();
        this.id = IdMaker.getNextId();

        PublicKeyList.getKeyList().put(this,SkPk.getPublic());
    }

    public void submitNonce(BigInteger nonce, HashMap<AbstractEntitiy, PublicKey> pid, byte[] signing, Initiator initiator) throws

            IOException,
            NoSuchAlgorithmException,
            InvalidKeyException,
            SignatureException,
            NoSuchProviderException,
            IllegalBlockSizeException,
            ClassNotFoundException,
            BadPaddingException,
            InvalidAlgorithmParameterException,
            NoSuchPaddingException, InvalidKeySpecException {

        this.pid = pid;
        ByteArrayOutputStream outputStream = stream(nonce);

        if (SignVerifyer.Verify(signing, PublicKeyList.getKeyList().get(initiator), outputStream.toByteArray( ))){

            this.pid = pid;
            ekdk = new KeyPairGenerationBKEM();

            ByteArrayOutputStream outputStream2 = stream(nonce);

            outputStream2.write(ekdk.getencryptionKey().getEncoded(false));

            this.sid = sidGenerator.GenerateSid(initiator.getId(), nonce, pid, ekdk.getencryptionKey());

            initiator.checkSid(ekdk.getencryptionKey(),Signing.Sign(SkPk,outputStream2.toByteArray()),this);
        }
        else{
            throw new IllegalArgumentException();
        }
    }

    public ByteArrayOutputStream stream(BigInteger nonce) throws IOException {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(nonce.toByteArray());
        for (AbstractEntitiy entity: pid.keySet()) {
            outputStream.write(entity.getId().toByteArray());
        }
        return outputStream;
    }

    public void Decapsulate(byte[] sid, ECPoint blindC, byte[] sign, Responder responder) throws

            IOException,
            NoSuchAlgorithmException,
            InvalidKeyException,
            SignatureException, NoSuchProviderException, InvalidKeySpecException {

        ByteArrayOutputStream outputStream3 = new ByteArrayOutputStream();
        outputStream3.write(sid);
        outputStream3.write(ekdk.getencryptionKey().getEncoded(false));
        outputStream3.write(blindC.getEncoded(false));

        if (SignVerifyer.Verify(sign,PublicKeyList.getKeyList().get(responder),outputStream3.toByteArray())){
            if (pid.containsKey(responder)){
                ECPoint blindk = KeyDecapsulation.Decapsulate(blindC,ekdk.getdecryptionKey());

                ByteArrayOutputStream outputStream4 = new ByteArrayOutputStream();
                outputStream4.write(sid);
                outputStream4.write(blindk.getEncoded(false));

                responder.UnblindAndKDF(sid, blindk, Signing.Sign(SkPk,outputStream4.toByteArray()),this);
            }
            else {
                throw new IllegalArgumentException();
            }
        }
        else {
            throw new IllegalArgumentException();
        }
    }
}
