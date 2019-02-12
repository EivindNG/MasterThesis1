package server;

import initiator.Initiator;
import org.bouncycastle.math.ec.ECPoint;
import responder.Responder;
import util.*;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.util.HashMap;

public class Server {

    private BigInteger id;
    private KeyPair SkPk;
    private KeyPairGenerationBKEM ekdk;
    private String sid;
    private HashMap pid;


    public Server() throws

            NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {

        PublicPrivateKeyGenerator privatepublickey = new PublicPrivateKeyGenerator();
        SkPk = privatepublickey.getPair();
        id = IdMaker.getNextId().add(BigInteger.valueOf(50));
        PublicKeyList.getKeyList().put(id,SkPk.getPublic());
    }

    public void submitNonce(BigInteger nonce, HashMap<BigInteger, PublicKey> pid, byte[] signing, Initiator initiator) throws

            IOException,
            NoSuchAlgorithmException,
            InvalidKeyException,
            SignatureException,
            NoSuchPaddingException,
            BadPaddingException,
            IllegalBlockSizeException,
            ClassNotFoundException, InvalidAlgorithmParameterException, NoSuchProviderException {

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
        outputStream.write(nonce.toByteArray());
        for (BigInteger key : pid.keySet()) {
            outputStream.write(key.toByteArray());
        }

        if (SignVerifyer.Verify(signing, PublicKeyList.getKeyList().get(initiator.getId()), outputStream.toByteArray( ))){

            this.pid = pid;
            ekdk = new KeyPairGenerationBKEM();

            ByteArrayOutputStream outputStream2 = new ByteArrayOutputStream( );
            outputStream2.write(nonce.toByteArray());
            for (BigInteger key : pid.keySet()) {
                outputStream2.write(key.toByteArray());
            }
            outputStream2.write(ekdk.getencryptionKey().getEncoded(false));

            this.sid = sidGenerator.GenerateSid(initiator.getId(), nonce, pid, ekdk.getencryptionKey());

            initiator.checkSid(ekdk.getencryptionKey(),Signing.Sign(SkPk,outputStream2.toByteArray()));
        }
        else{
            throw new IllegalArgumentException();
        }
    }

    public void Decapsulate(String sid, ECPoint blindC, byte[] sign, Responder responder) throws

            IOException,
            NoSuchAlgorithmException,
            InvalidKeyException,
            SignatureException, NoSuchProviderException {

        ByteArrayOutputStream outputStream3 = new ByteArrayOutputStream();
        outputStream3.write(sid.getBytes());
        outputStream3.write(ekdk.getencryptionKey().getEncoded(false));
        outputStream3.write(blindC.getEncoded(false));

        if (SignVerifyer.Verify(sign,PublicKeyList.getKeyList().get(responder.getId()),outputStream3.toByteArray())){
            if (pid.containsKey(responder.getId())){
                ECPoint blindk = KeyDecapsulation.Decapsulate(blindC,ekdk.getdecryptionKey());

                ByteArrayOutputStream outputStream4 = new ByteArrayOutputStream();
                outputStream4.write(sid.getBytes());
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

    public BigInteger getId() {
        return id;
    }

}
